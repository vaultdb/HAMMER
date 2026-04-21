// GPU FHE TPC-H filter benchmark — all 6 queries (Q1, Q4, Q5, Q6, Q12, Q19).
// Standalone test using HEonGPU -- no multi-party setup, no OpenFHE dependency.
//
// Usage:
//   ./bin/gpu_fhe_tpch_test --unioned_db=tpch_unioned_15000
//   ./bin/gpu_fhe_tpch_test --unioned_db=tpch_unioned_15000 --filter="*q1*"
//   ./bin/gpu_fhe_tpch_test --unioned_db=tpch_unioned_150 --validation=false

#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <pqxx/pqxx>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "gpu_fhe_backend.cuh"
#include "gpu_fhe_comparator.cuh"
#include "gpu_fhe_aggregate.cuh"

DECLARE_string(unioned_db);
DECLARE_bool(validation);
DECLARE_string(filter);

namespace {

// ═══════════════════════════════════════════════════════════════
// BFV / HEonGPU parameters
// mult_depth=14: L_eff ≈ 11, covers Q19 (depth ~10)
// ═══════════════════════════════════════════════════════════════
constexpr size_t   kPolyModulusDegree = 32768;
constexpr uint64_t kPlainModulus      = 1179649;
constexpr uint32_t kMultDepth         = 14;
const char* kBaseDate = "1992-01-01";

// ═══════════════════════════════════════════════════════════════
// TeeStream: dual-output to stdout + log file
// ═══════════════════════════════════════════════════════════════
class TeeStream {
public:
    TeeStream() : file_(nullptr) {}
    bool open(const std::string& path) {
        file_.reset(new std::ofstream(path, std::ios::app));
        return file_->is_open();
    }
    template <typename T>
    TeeStream& operator<<(const T& val) {
        std::cout << val;
        if (file_ && file_->is_open()) *file_ << val;
        return *this;
    }
    TeeStream& operator<<(std::ostream& (*manip)(std::ostream&)) {
        std::cout << manip;
        if (file_ && file_->is_open()) *file_ << manip;
        return *this;
    }
    void flush() {
        std::cout.flush();
        if (file_ && file_->is_open()) file_->flush();
    }
private:
    std::unique_ptr<std::ofstream> file_;
};

TeeStream gLog;

// ═══════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════

std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S%z");
    return oss.str();
}

int64_t dateToDaysSinceBase(const std::string& date_str) {
    auto parse = [](const std::string& s) {
        std::tm t{};
        int y, m, d;
        if (std::sscanf(s.c_str(), "%d-%d-%d", &y, &m, &d) != 3)
            throw std::runtime_error("Bad date: " + s);
        t.tm_year = y - 1900;
        t.tm_mon  = m - 1;
        t.tm_mday = d;
        t.tm_isdst = -1;
        return t;
    };
    std::tm base_tm = parse(kBaseDate);
    std::tm curr_tm = parse(date_str);
    return static_cast<int64_t>(mktime(&curr_tm) / (24 * 3600))
         - static_cast<int64_t>(mktime(&base_tm) / (24 * 3600));
}

// ═══════════════════════════════════════════════════════════════
// Data loading from Postgres
// ═══════════════════════════════════════════════════════════════

struct ColumnData {
    std::vector<std::vector<int64_t>> columns;   // columns[col_idx][row]
    size_t row_count = 0;
};

ColumnData loadFromPostgres(const std::string& db, const std::string& sql, size_t num_cols) {
    auto t1 = std::chrono::high_resolution_clock::now();

    pqxx::connection conn("user=vaultdb dbname=" + db);
    pqxx::work txn(conn);
    pqxx::result res = txn.exec(sql);
    txn.commit();
    conn.close();

    ColumnData data;
    data.row_count = res.size();
    data.columns.resize(num_cols);
    for (auto& col : data.columns) col.reserve(data.row_count);
    for (const auto& row : res) {
        for (size_t c = 0; c < num_cols; ++c)
            data.columns[c].push_back(row[c].as<int64_t>());
    }

    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    gLog << "[Timing] Operator #0 (FheTableScan) Runtime: "
         << std::fixed << std::setprecision(2) << static_cast<double>(ms)
         << " ms, rows=" << data.row_count << std::endl;

    return data;
}

// ═══════════════════════════════════════════════════════════════
// Type aliases
// ═══════════════════════════════════════════════════════════════
using BfvCt = heongpu::Ciphertext<heongpu::Scheme::BFV>;
using BfvPt = heongpu::Plaintext<heongpu::Scheme::BFV>;

// ═══════════════════════════════════════════════════════════════
// Threshold encryption
// ═══════════════════════════════════════════════════════════════

std::vector<BfvCt>
encryptThresholdDigits(int64_t threshold, size_t radix_base, size_t num_digits) {
    auto& backend   = vaultdb::GpuFheBackend::getInstance();
    auto& ctx       = backend.context();
    auto& encoder   = backend.encoder();
    auto& encryptor = backend.encryptor();
    size_t slots    = backend.slotCount();

    auto digits = vaultdb::encodeRadix(threshold, radix_base, num_digits);
    std::vector<BfvCt> ciphers;
    ciphers.reserve(num_digits);
    for (size_t i = 0; i < num_digits; ++i) {
        std::vector<int64_t> digit_vec(slots, digits[i]);
        BfvPt pt(ctx);
        encoder.encode(pt, digit_vec);
        BfvCt ct(ctx);
        encryptor.encrypt(ct, pt);
        ciphers.push_back(std::move(ct));
    }
    return ciphers;
}

// ═══════════════════════════════════════════════════════════════
// GPU AND / OR helpers (ct-ct)
// ═══════════════════════════════════════════════════════════════

BfvCt gpuAnd(BfvCt& a, BfvCt& b) {
    auto& backend = vaultdb::GpuFheBackend::getInstance();
    auto& ctx   = backend.context();
    auto& arith = backend.arithOp();
    auto& relin = backend.relinKey();
    BfvCt result(ctx);
    arith.multiply(a, b, result);
    arith.relinearize_inplace(result, relin);
    return result;
}

BfvCt gpuOr(BfvCt& a, BfvCt& b) {
    auto& backend = vaultdb::GpuFheBackend::getInstance();
    auto& ctx   = backend.context();
    auto& arith = backend.arithOp();
    BfvCt result(ctx);
    arith.add(a, b, result);
    return result;
}

// ═══════════════════════════════════════════════════════════════
// Chunk-level predicate helpers
// ═══════════════════════════════════════════════════════════════

std::vector<int64_t> chunkSlice(const std::vector<int64_t>& col,
                                 size_t offset, size_t rows) {
    return {col.begin() + offset, col.begin() + offset + rows};
}

// Run a single comparison predicate on a chunk.
BfvCt runComparison(vaultdb::GpuCompareOp op,
                    const std::vector<BfvCt>& threshold_ciphers,
                    const std::vector<int64_t>& chunk_values,
                    size_t pack_slots, size_t radix_base, size_t num_digits) {
    auto rc = vaultdb::buildRadixColumns(chunk_values, radix_base, num_digits, pack_slots);
    switch (op) {
        case vaultdb::GpuCompareOp::LESS_EQUAL:
            return vaultdb::gpuPolynomialComparisonLe(threshold_ciphers, rc, pack_slots, radix_base);
        case vaultdb::GpuCompareOp::LESS_THAN:
            return vaultdb::gpuPolynomialComparisonLt(threshold_ciphers, rc, pack_slots, radix_base);
        case vaultdb::GpuCompareOp::GREATER_EQUAL:
            return vaultdb::gpuPolynomialComparisonGe(threshold_ciphers, rc, pack_slots, radix_base);
        case vaultdb::GpuCompareOp::GREATER_THAN:
            return vaultdb::gpuPolynomialComparisonGt(threshold_ciphers, rc, pack_slots, radix_base);
        case vaultdb::GpuCompareOp::EQUAL:
            return vaultdb::gpuPolynomialComparisonEqual(threshold_ciphers, rc, pack_slots, radix_base);
    }
    throw std::runtime_error("Unknown GpuCompareOp");
}

// Run IN predicate: OR of multiple equality checks on the same column.
BfvCt runInPredicate(const std::vector<std::vector<BfvCt>>& threshold_list,
                     const std::vector<int64_t>& chunk_values,
                     size_t pack_slots, size_t radix_base, size_t num_digits) {
    auto rc = vaultdb::buildRadixColumns(chunk_values, radix_base, num_digits, pack_slots);
    auto result = vaultdb::gpuPolynomialComparisonEqual(
        threshold_list[0], rc, pack_slots, radix_base);
    for (size_t i = 1; i < threshold_list.size(); ++i) {
        auto eq_i = vaultdb::gpuPolynomialComparisonEqual(
            threshold_list[i], rc, pack_slots, radix_base);
        result = gpuOr(result, eq_i);
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════
// Decrypt helper
// ═══════════════════════════════════════════════════════════════

std::vector<int64_t> gpuDecrypt(BfvCt& ct, size_t num_rows) {
    auto& backend   = vaultdb::GpuFheBackend::getInstance();
    auto& ctx       = backend.context();
    auto& encoder   = backend.encoder();
    auto& decryptor = backend.decryptor();
    BfvPt pt(ctx);
    decryptor.decrypt(pt, ct);
    std::vector<int64_t> full(backend.slotCount());
    encoder.decode(full, pt);
    full.resize(num_rows);
    return full;
}

// ═══════════════════════════════════════════════════════════════
// Generic filter-test driver: chunk loop, timing, validation
// ═══════════════════════════════════════════════════════════════

void runFilterTest(
    const ColumnData& data,
    const std::function<BfvCt(size_t off, size_t rows, size_t ps)>& chunk_filter,
    const std::function<int64_t(size_t row)>& expected_fn,
    const std::string& qname)
{
    auto& backend    = vaultdb::GpuFheBackend::getInstance();
    size_t pack_slots = backend.slotCount();
    size_t N          = data.row_count;
    size_t num_chunks = (N + pack_slots - 1) / pack_slots;

    gLog << "[" << qname << "] " << N << " rows, " << num_chunks << " chunks, "
         << pack_slots << " slots/ct" << std::endl;

    long long total_ms = 0;
    std::vector<std::vector<int64_t>> all_dec;

    for (size_t c = 0; c < num_chunks; ++c) {
        size_t off  = c * pack_slots;
        size_t rows = std::min(pack_slots, N - off);

        auto t1 = std::chrono::high_resolution_clock::now();
        auto result = chunk_filter(off, rows, pack_slots);
        auto t2 = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        total_ms += ms;

        if (FLAGS_validation)
            all_dec.push_back(gpuDecrypt(result, rows));
    }

    // Timing output matching extract_timing() regex in common.sh
    gLog << "[Timing] Operator #1 (FheFilter) Runtime: "
         << std::fixed << std::setprecision(2) << static_cast<double>(total_ms)
         << " ms" << std::endl;
    gLog << "[GpuFheTpchTest] Runtime: "
         << std::fixed << std::setprecision(2) << static_cast<double>(total_ms) / 1000.0
         << " sec" << std::endl;

    if (FLAGS_validation) {
        size_t match = 0, mismatch = 0, pass_count = 0;
        size_t global_idx = 0;
        for (size_t c = 0; c < all_dec.size(); ++c) {
            for (size_t i = 0; i < all_dec[c].size(); ++i, ++global_idx) {
                int64_t exp = expected_fn(global_idx);
                int64_t got = all_dec[c][i];
                if (exp) ++pass_count;
                if (got == exp) {
                    ++match;
                } else {
                    ++mismatch;
                    if (mismatch <= 10)
                        gLog << "  Mismatch row " << global_idx
                             << ": expected=" << exp << " got=" << got << std::endl;
                }
            }
        }
        gLog << "[Validation] " << qname << ": " << N << " rows: "
             << match << " match, " << mismatch << " mismatch, "
             << pass_count << " pass filter" << std::endl;
        EXPECT_EQ(mismatch, 0) << mismatch << " rows did not match in " << qname;
    }
}

// ═══════════════════════════════════════════════════════════════
// Aggregate support types + helpers
// ═══════════��═══════════════════════════════════════════════════

enum class AggType { SUM, COUNT };

struct AggSpec {
    AggType type;
    std::string col_name;   // SUM: value column name; COUNT: ref column for bin info
    std::string alias;      // output name
};

// Compute bin metadata from sorted group keys.
// All col_names get identical bin info (continuous packing → same layout).
std::vector<vaultdb::GpuBinGroupMetadata> computeBinMetadata(
    const std::vector<int64_t>& group_keys,
    size_t pack_slots,
    const std::vector<std::string>& col_names)
{
    std::vector<vaultdb::GpuBinGroupMetadata> result;
    if (group_keys.empty()) return result;

    size_t start = 0;
    for (size_t i = 1; i <= group_keys.size(); ++i) {
        if (i == group_keys.size() || group_keys[i] != group_keys[start]) {
            vaultdb::GpuBinGroupMetadata meta;
            meta.group_key_values = {group_keys[start]};
            meta.original_start_row = start;
            meta.original_end_row = i - 1;

            vaultdb::GpuColumnBinInfo bin_info;
            size_t start_chunk = start / pack_slots;
            size_t end_chunk   = (i - 1) / pack_slots;
            bin_info.start_chunk_idx   = start_chunk;
            bin_info.end_chunk_idx     = end_chunk;
            bin_info.total_packed_count = i - start;

            for (size_t c = start_chunk; c <= end_chunk; ++c) {
                size_t slot_start = (c == start_chunk) ? (start % pack_slots) : 0;
                size_t slot_end   = (c == end_chunk) ? ((i - 1) % pack_slots)
                                                     : (pack_slots - 1);
                bin_info.chunk_slot_ranges[c] = {slot_start, slot_end};
            }

            for (const auto& name : col_names)
                meta.column_bin_info[name] = bin_info;

            result.push_back(std::move(meta));
            start = i;
        }
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════
// Filter + Aggregate driver
// ═══════════════════════════════════════════════════════════════

void runFilterAggregateTest(
    const ColumnData& data,
    const std::function<BfvCt(size_t off, size_t rows, size_t ps)>& chunk_filter,
    const std::function<int64_t(size_t row)>& expected_fn,
    size_t group_key_col,
    const std::map<std::string, size_t>& agg_value_cols,
    const std::vector<AggSpec>& agg_specs,
    const std::string& qname)
{
    auto& backend     = vaultdb::GpuFheBackend::getInstance();
    size_t pack_slots = backend.slotCount();
    size_t N          = data.row_count;
    size_t num_chunks = (N + pack_slots - 1) / pack_slots;

    gLog << "[" << qname << "] " << N << " rows, " << num_chunks << " chunks, "
         << pack_slots << " slots/ct" << std::endl;

    // ── Phase 1: Filter ──────────────────────────────────────────
    long long filter_ms = 0;
    std::vector<BfvCt> chunk_results;
    std::vector<size_t> chunk_rows_vec;
    std::vector<std::vector<int64_t>> all_dec;
    chunk_results.reserve(num_chunks);
    chunk_rows_vec.reserve(num_chunks);

    for (size_t c = 0; c < num_chunks; ++c) {
        size_t off  = c * pack_slots;
        size_t rows = std::min(pack_slots, N - off);

        auto t1 = std::chrono::high_resolution_clock::now();
        auto result = chunk_filter(off, rows, pack_slots);
        auto t2 = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        filter_ms += ms;

        chunk_results.push_back(std::move(result));
        chunk_rows_vec.push_back(rows);

        if (FLAGS_validation)
            all_dec.push_back(gpuDecrypt(chunk_results.back(), rows));
    }

    gLog << "[Timing] Operator #1 (FheFilter) Runtime: "
         << std::fixed << std::setprecision(2) << static_cast<double>(filter_ms)
         << " ms" << std::endl;

    // Validate filter indicator
    if (FLAGS_validation) {
        size_t match = 0, mismatch = 0, pass_count = 0;
        size_t global_idx = 0;
        for (size_t c = 0; c < all_dec.size(); ++c) {
            for (size_t i = 0; i < all_dec[c].size(); ++i, ++global_idx) {
                int64_t exp = expected_fn(global_idx);
                int64_t got = all_dec[c][i];
                if (exp) ++pass_count;
                if (got == exp) {
                    ++match;
                } else {
                    ++mismatch;
                    if (mismatch <= 10)
                        gLog << "  Mismatch row " << global_idx
                             << ": expected=" << exp << " got=" << got << std::endl;
                }
            }
        }
        gLog << "[Validation] " << qname << " filter: " << N << " rows: "
             << match << " match, " << mismatch << " mismatch, "
             << pass_count << " pass filter" << std::endl;
        EXPECT_EQ(mismatch, 0) << mismatch << " rows did not match in " << qname;
    }

    // ── Phase 2: Aggregate ──────────────────────────────────────
    auto agg_t1 = std::chrono::high_resolution_clock::now();

    // 2a: Wrap filter results as GpuFheColumn (single channel)
    vaultdb::GpuFheColumn indicator_col("indicator");
    for (size_t i = 0; i < chunk_results.size(); ++i) {
        indicator_col.addChunk(vaultdb::GpuFheColumnChunk(
            std::move(chunk_results[i]), chunk_rows_vec[i]));
    }

    // 2b: Collect all column names referenced by agg specs
    std::vector<std::string> all_col_names;
    {
        std::set<std::string> names_set;
        for (const auto& spec : agg_specs)
            names_set.insert(spec.col_name);
        all_col_names.assign(names_set.begin(), names_set.end());
    }

    // 2c: Compute bin metadata from sorted group keys
    const auto& group_keys = data.columns[group_key_col];
    auto bin_metadata = computeBinMetadata(group_keys, pack_slots, all_col_names);
    size_t num_groups = bin_metadata.size();
    gLog << "[" << qname << "] Aggregate: " << num_groups << " groups, "
         << agg_specs.size() << " agg specs" << std::endl;

    // 2d: Precompute weighted values for SUM columns
    std::map<std::string, vaultdb::GpuFheColumn> weighted_cols;
    for (const auto& spec : agg_specs) {
        if (spec.type == AggType::SUM &&
            weighted_cols.find(spec.col_name) == weighted_cols.end()) {
            auto it = agg_value_cols.find(spec.col_name);
            if (it == agg_value_cols.end())
                throw std::runtime_error("SUM column not found: " + spec.col_name);
            weighted_cols.emplace(spec.col_name,
                vaultdb::gpuPrecomputeWeightedValue(
                    indicator_col, data.columns[it->second],
                    spec.col_name, pack_slots));
        }
    }

    // 2e: Run aggregate for each group × each spec
    size_t channel = 0;
    auto& ctx   = backend.context(channel);
    auto& arith = backend.arithOp(channel);

    // Per-alias accumulator (packs all groups' results at different target slots)
    std::map<std::string, BfvCt> accumulators;

    for (size_t g = 0; g < num_groups; ++g) {
        size_t target_slot = g;
        const auto& group_meta = bin_metadata[g];

        for (const auto& spec : agg_specs) {
            BfvCt group_result(ctx);

            if (spec.type == AggType::SUM) {
                group_result = vaultdb::gpuAggregateGroupSum(
                    weighted_cols.at(spec.col_name), group_meta,
                    spec.col_name, target_slot, pack_slots, channel);
            } else {
                group_result = vaultdb::gpuAggregateGroupCount(
                    indicator_col, group_meta, spec.col_name,
                    target_slot, pack_slots, channel);
            }

            auto acc_it = accumulators.find(spec.alias);
            if (acc_it == accumulators.end()) {
                accumulators.emplace(spec.alias, std::move(group_result));
            } else {
                BfvCt sum(ctx);
                arith.add(acc_it->second, group_result, sum);
                acc_it->second = std::move(sum);
            }
        }
    }

    auto agg_t2 = std::chrono::high_resolution_clock::now();
    auto agg_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        agg_t2 - agg_t1).count();

    gLog << "[Timing] Operator #2 (FheAggregate) Runtime: "
         << std::fixed << std::setprecision(2) << static_cast<double>(agg_ms)
         << " ms" << std::endl;

    double total_sec = static_cast<double>(filter_ms + agg_ms) / 1000.0;
    gLog << "[GpuFheTpchTest] Runtime: "
         << std::fixed << std::setprecision(2) << total_sec
         << " sec" << std::endl;

    // Print aggregate result summary (decrypt accumulators)
    if (FLAGS_validation) {
        gLog << "[" << qname << "] Aggregate results (mod p=" << kPlainModulus
             << ", " << num_groups << " groups):" << std::endl;
        for (auto& [alias, ct] : accumulators) {
            auto dec = gpuDecrypt(ct, std::min(num_groups, pack_slots));
            gLog << "  " << alias << ": [";
            for (size_t g = 0; g < num_groups && g < 10; ++g) {
                if (g > 0) gLog << ", ";
                gLog << dec[g];
            }
            if (num_groups > 10) gLog << ", ...";
            gLog << "]" << std::endl;
        }
    }
}

}  // namespace

// ═══════════════════════════════════════════════════════════════
// Test fixture
// ═══════════════════════════════════════════════════════════════

class GpuFheTpchTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        vaultdb::GpuBfvParams params;
        params.poly_modulus_degree = kPolyModulusDegree;
        params.plain_modulus       = kPlainModulus;
        params.mult_depth          = kMultDepth;

        auto& backend = vaultdb::GpuFheBackend::getInstance();
        if (!backend.isInitialized()) {
            gLog << "[GpuFheTpchTest] Initializing HEonGPU backend (ring="
                 << kPolyModulusDegree << ", depth=" << kMultDepth << ")..."
                 << std::endl;
            auto t1 = std::chrono::high_resolution_clock::now();
            backend.initialize(params);
            backend.generateKeys();
            auto t2 = std::chrono::high_resolution_clock::now();
            gLog << "[Timing] Backend init + keygen: "
                 << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count()
                 << " ms" << std::endl;
        }
    }
};

// ═══════════════════════════════════════════════════════════════
// Q1: l_shipdate <= '1998-08-03'   (1 predicate, base4 6-digit)
// ═══════════════════════════════════════════════════════════════

TEST_F(GpuFheTpchTest, fhe_tpch_q1) {
    // Cols: 0=shipdate, 1=group_key(returnflag*2+linestatus),
    //       2=qty, 3=price, 4=disc_price, 5=charge, 6=discount
    auto data = loadFromPostgres(FLAGS_unioned_db,
        "SELECT (l_shipdate - DATE '1992-01-01'),"
        "(CASE l_returnflag WHEN 'A' THEN 0 WHEN 'N' THEN 1 WHEN 'R' THEN 2 END)*2"
        "+(CASE l_linestatus WHEN 'F' THEN 0 WHEN 'O' THEN 1 END),"
        "l_quantity::bigint,"
        "ROUND(l_extendedprice*100)::bigint,"
        "ROUND(l_extendedprice*(1-l_discount)*100)::bigint,"
        "ROUND(l_extendedprice*(1-l_discount)*(1+l_tax)*100)::bigint,"
        "ROUND(l_discount*100)::bigint "
        "FROM lineitem ORDER BY 2, l_orderkey, l_linenumber", 7);
    ASSERT_GT(data.row_count, 0u);

    int64_t T = dateToDaysSinceBase("1998-08-03");
    auto tc = encryptThresholdDigits(T, 4, 6);

    std::map<std::string, size_t> agg_value_cols = {
        {"qty", 2}, {"price", 3}, {"disc_price", 4}, {"charge", 5}, {"discount", 6}};
    std::vector<AggSpec> agg_specs = {
        {AggType::SUM,   "qty",        "sum_qty"},
        {AggType::SUM,   "price",      "sum_base_price"},
        {AggType::SUM,   "disc_price", "sum_disc_price"},
        {AggType::SUM,   "charge",     "sum_charge"},
        {AggType::SUM,   "discount",   "sum_discount"},
        {AggType::COUNT, "qty",        "count_order"},
    };

    runFilterAggregateTest(data,
        [&](size_t off, size_t rows, size_t ps) {
            return runComparison(vaultdb::GpuCompareOp::LESS_EQUAL,
                tc, chunkSlice(data.columns[0], off, rows), ps, 4, 6);
        },
        [&](size_t i) -> int64_t { return data.columns[0][i] <= T ? 1 : 0; },
        1, agg_value_cols, agg_specs, "Q1");
}

// ═══════════════════════════════════════════════════════════════
// Q4: o_orderdate >= '1993-07-01' AND < '1993-10-01'
// ═══════════════════════════════════════════════════════════════

TEST_F(GpuFheTpchTest, fhe_tpch_q4) {
    // Cols: 0=orderdate, 1=group_key(orderpriority)
    auto data = loadFromPostgres(FLAGS_unioned_db,
        "SELECT (o_orderdate - DATE '1992-01-01'),"
        "CASE o_orderpriority"
        " WHEN '1-URGENT' THEN 0 WHEN '2-HIGH' THEN 1 WHEN '3-MEDIUM' THEN 2"
        " WHEN '4-NOT SPECIFIED' THEN 3 WHEN '5-LOW' THEN 4 END "
        "FROM orders o JOIN lineitem l ON l.l_orderkey = o.o_orderkey "
        "WHERE l_commitdate < l_receiptdate "
        "ORDER BY 2, o.o_orderkey, l.l_orderkey, l.l_linenumber", 2);
    ASSERT_GT(data.row_count, 0u);

    int64_t T1 = dateToDaysSinceBase("1993-07-01");
    int64_t T2 = dateToDaysSinceBase("1993-10-01");
    auto tc_ge = encryptThresholdDigits(T1, 4, 6);
    auto tc_lt = encryptThresholdDigits(T2, 4, 6);

    std::map<std::string, size_t> agg_value_cols;  // COUNT only — no SUM columns
    std::vector<AggSpec> agg_specs = {
        {AggType::COUNT, "indicator", "order_count"},
    };

    runFilterAggregateTest(data,
        [&](size_t off, size_t rows, size_t ps) {
            auto v = chunkSlice(data.columns[0], off, rows);
            auto ge = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_ge, v, ps, 4, 6);
            auto lt = runComparison(vaultdb::GpuCompareOp::LESS_THAN, tc_lt, v, ps, 4, 6);
            return gpuAnd(ge, lt);
        },
        [&](size_t i) -> int64_t {
            return (data.columns[0][i] >= T1 && data.columns[0][i] < T2) ? 1 : 0;
        },
        1, agg_value_cols, agg_specs, "Q4");
}

// ═══════════════════════════════════════════════════════════════
// Q5: r_name = 'EUROPE' AND o_orderdate in [1993-01-01, 1994-01-01]
// ═══════════════════════════════════════════════════════════════

TEST_F(GpuFheTpchTest, fhe_tpch_q5) {
    // Cols: 0=region_enc, 1=orderdate, 2=group_key(nationkey), 3=revenue
    auto data = loadFromPostgres(FLAGS_unioned_db,
        "SELECT "
        "CASE r.r_name "
        " WHEN 'AFRICA' THEN 0 WHEN 'AMERICA' THEN 1 WHEN 'ASIA' THEN 2"
        " WHEN 'EUROPE' THEN 3 WHEN 'MIDDLE EAST' THEN 4 END,"
        "(o_orderdate - DATE '1992-01-01'),"
        "n.n_nationkey::bigint,"
        "ROUND(l_extendedprice*(1-l_discount)*100)::bigint "
        "FROM customer c "
        "JOIN orders o ON c.c_custkey = o.o_custkey "
        "JOIN lineitem l ON l.l_orderkey = o.o_orderkey "
        "JOIN supplier s ON l.l_suppkey = s.s_suppkey "
        "JOIN nation n ON s.s_nationkey = n.n_nationkey "
        "JOIN region r ON n.n_regionkey = r.r_regionkey "
        "WHERE c.c_nationkey = s.s_nationkey "
        "ORDER BY 3, o.o_orderkey, l.l_orderkey, l.l_linenumber", 4);
    ASSERT_GT(data.row_count, 0u);

    int64_t T_region  = 3;  // EUROPE
    int64_t T_date_ge = dateToDaysSinceBase("1993-01-01");
    int64_t T_date_lt = dateToDaysSinceBase("1994-01-01");

    auto tc_region = encryptThresholdDigits(T_region, 5, 1);
    auto tc_ge     = encryptThresholdDigits(T_date_ge, 4, 6);
    auto tc_lt     = encryptThresholdDigits(T_date_lt, 4, 6);

    std::map<std::string, size_t> agg_value_cols = {{"revenue", 3}};
    std::vector<AggSpec> agg_specs = {
        {AggType::SUM, "revenue", "revenue"},
    };

    runFilterAggregateTest(data,
        [&](size_t off, size_t rows, size_t ps) {
            auto v0 = chunkSlice(data.columns[0], off, rows);
            auto v1 = chunkSlice(data.columns[1], off, rows);
            auto eq = runComparison(vaultdb::GpuCompareOp::EQUAL, tc_region, v0, ps, 5, 1);
            auto ge = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_ge, v1, ps, 4, 6);
            auto lt = runComparison(vaultdb::GpuCompareOp::LESS_THAN, tc_lt, v1, ps, 4, 6);
            auto dr = gpuAnd(ge, lt);
            return gpuAnd(eq, dr);
        },
        [&](size_t i) -> int64_t {
            return (data.columns[0][i] == T_region &&
                    data.columns[1][i] >= T_date_ge &&
                    data.columns[1][i] <  T_date_lt) ? 1 : 0;
        },
        2, agg_value_cols, agg_specs, "Q5");
}

// ═══════════════════════════════════════════════════════════════
// Q6: date range AND discount range AND l_quantity < 24
// ═══════════════════════════════════════════════════════════════

TEST_F(GpuFheTpchTest, fhe_tpch_q6) {
    // Cols: 0=shipdate, 1=discount, 2=qty, 3=group_key(=1), 4=revenue
    auto data = loadFromPostgres(FLAGS_unioned_db,
        "SELECT (l_shipdate - DATE '1992-01-01'),"
        "       ROUND(l_discount * 100)::int,"
        "       l_quantity::int,"
        "       1::bigint,"
        "       ROUND(l_extendedprice * l_discount * 100)::bigint "
        "FROM lineitem ORDER BY l_orderkey, l_linenumber", 5);
    ASSERT_GT(data.row_count, 0u);

    int64_t T_dge   = dateToDaysSinceBase("1997-01-01");
    int64_t T_dlt   = dateToDaysSinceBase("1998-01-01");
    int64_t T_disc_ge = 2;   // 0.02 * 100
    int64_t T_disc_le = 4;   // 0.04 * 100
    int64_t T_qty_lt  = 24;

    auto tc_dge     = encryptThresholdDigits(T_dge, 4, 6);
    auto tc_dlt     = encryptThresholdDigits(T_dlt, 4, 6);
    auto tc_disc_ge = encryptThresholdDigits(T_disc_ge, 4, 2);
    auto tc_disc_le = encryptThresholdDigits(T_disc_le, 4, 2);
    auto tc_qty     = encryptThresholdDigits(T_qty_lt, 4, 3);

    std::map<std::string, size_t> agg_value_cols = {{"revenue", 4}};
    std::vector<AggSpec> agg_specs = {
        {AggType::SUM, "revenue", "revenue"},
    };

    runFilterAggregateTest(data,
        [&](size_t off, size_t rows, size_t ps) {
            auto vd = chunkSlice(data.columns[0], off, rows);
            auto vdisc = chunkSlice(data.columns[1], off, rows);
            auto vqty  = chunkSlice(data.columns[2], off, rows);

            auto p1 = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_dge, vd, ps, 4, 6);
            auto p2 = runComparison(vaultdb::GpuCompareOp::LESS_THAN, tc_dlt, vd, ps, 4, 6);
            auto p3 = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_disc_ge, vdisc, ps, 4, 2);
            auto p4 = runComparison(vaultdb::GpuCompareOp::LESS_EQUAL, tc_disc_le, vdisc, ps, 4, 2);
            auto p5 = runComparison(vaultdb::GpuCompareOp::LESS_THAN, tc_qty, vqty, ps, 4, 3);

            // Balanced AND tree: (p1*p2) * (p3*p4) * p5
            auto a1 = gpuAnd(p1, p2);
            auto a2 = gpuAnd(p3, p4);
            auto a3 = gpuAnd(a1, a2);
            return gpuAnd(a3, p5);
        },
        [&](size_t i) -> int64_t {
            return (data.columns[0][i] >= T_dge  && data.columns[0][i] < T_dlt &&
                    data.columns[1][i] >= T_disc_ge && data.columns[1][i] <= T_disc_le &&
                    data.columns[2][i] <  T_qty_lt) ? 1 : 0;
        },
        3, agg_value_cols, agg_specs, "Q6");
}

// ═══════════════════════════════════════════════════════════════
// Q12: l_shipmode IN ('TRUCK','AIR REG') AND l_receiptdate range
// ═══════════════════════════════════════════════════════════════

TEST_F(GpuFheTpchTest, fhe_tpch_q12) {
    // Cols: 0=shipmode_enc (also group_key), 1=receiptdate, 2=high_count, 3=low_count
    auto data = loadFromPostgres(FLAGS_unioned_db,
        "SELECT "
        "CASE l.l_shipmode "
        " WHEN 'MAIL' THEN 0 WHEN 'SHIP' THEN 1 WHEN 'RAIL' THEN 2"
        " WHEN 'AIR' THEN 3 WHEN 'TRUCK' THEN 4 WHEN 'AIR REG' THEN 5 WHEN 'FOB' THEN 6 END,"
        "(l.l_receiptdate - DATE '1992-01-01'),"
        "CASE WHEN o.o_orderpriority IN ('1-URGENT','2-HIGH') THEN 1 ELSE 0 END,"
        "CASE WHEN o.o_orderpriority NOT IN ('1-URGENT','2-HIGH') THEN 1 ELSE 0 END "
        "FROM orders o, lineitem l "
        "WHERE o.o_orderkey = l.l_orderkey "
        "AND l.l_commitdate < l.l_receiptdate "
        "AND l.l_shipdate < l.l_commitdate "
        "ORDER BY 1, o.o_orderkey, l.l_orderkey, l.l_linenumber", 4);
    ASSERT_GT(data.row_count, 0u);

    int64_t T_mode1   = 4;   // TRUCK
    int64_t T_mode2   = 5;   // AIR REG
    int64_t T_date_ge = dateToDaysSinceBase("1994-01-01");
    int64_t T_date_lt = dateToDaysSinceBase("1995-01-01");

    auto tc_m1  = encryptThresholdDigits(T_mode1, 4, 2);
    auto tc_m2  = encryptThresholdDigits(T_mode2, 4, 2);
    auto tc_ge  = encryptThresholdDigits(T_date_ge, 4, 6);
    auto tc_lt  = encryptThresholdDigits(T_date_lt, 4, 6);
    std::vector<std::vector<BfvCt>> in_modes = {tc_m1, tc_m2};

    std::map<std::string, size_t> agg_value_cols = {
        {"high_count", 2}, {"low_count", 3}};
    std::vector<AggSpec> agg_specs = {
        {AggType::SUM, "high_count", "high_line_count"},
        {AggType::SUM, "low_count",  "low_line_count"},
    };

    runFilterAggregateTest(data,
        [&](size_t off, size_t rows, size_t ps) {
            auto vm = chunkSlice(data.columns[0], off, rows);
            auto vd = chunkSlice(data.columns[1], off, rows);
            auto p_in = runInPredicate(in_modes, vm, ps, 4, 2);
            auto p_ge = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_ge, vd, ps, 4, 6);
            auto p_lt = runComparison(vaultdb::GpuCompareOp::LESS_THAN, tc_lt, vd, ps, 4, 6);
            auto dr   = gpuAnd(p_ge, p_lt);
            return gpuAnd(p_in, dr);
        },
        [&](size_t i) -> int64_t {
            auto m = data.columns[0][i];
            auto d = data.columns[1][i];
            return ((m == T_mode1 || m == T_mode2) &&
                    d >= T_date_ge && d < T_date_lt) ? 1 : 0;
        },
        0, agg_value_cols, agg_specs, "Q12");
}

// ═══════════════════════════════════════════════════════════════
// Q19: DNF — common AND × (G0 + G1 + G2)
//   Common: l_shipinstruct='DELIVER IN PERSON', l_shipmode IN ('AIR','AIR REG'), p_size>=1
//   G0: Brand#41, SM containers, qty [2,12], psize<=5
//   G1: Brand#13, MED containers, qty [14,24], psize<=10
//   G2: Brand#55, LG containers, qty [23,33], psize<=15
// ═══════════════════════════════════════════════════════════════

TEST_F(GpuFheTpchTest, fhe_tpch_q19) {
    // Cols: 0=brand, 1=container, 2=qty, 3=psize, 4=mode, 5=instruct,
    //       6=group_key(=1), 7=revenue
    auto data = loadFromPostgres(FLAGS_unioned_db,
        "SELECT "
        // p_brand → integer encoding (Brand#XY → (X-1)*5 + (Y-1))
        "((SUBSTRING(p.p_brand FROM 7 FOR 1)::int - 1) * 5 "
        " + (SUBSTRING(p.p_brand FROM 8 FOR 1)::int - 1)),"
        // p_container → integer encoding (prefix*8 + suffix)
        "(CASE WHEN p.p_container LIKE 'SM %' THEN 0"
        " WHEN p.p_container LIKE 'MED %' THEN 8"
        " WHEN p.p_container LIKE 'LG %' THEN 16"
        " WHEN p.p_container LIKE 'JUMBO %' THEN 24"
        " WHEN p.p_container LIKE 'WRAP %' THEN 32 END"
        " + CASE SPLIT_PART(p.p_container,' ',2)"
        " WHEN 'CASE' THEN 0 WHEN 'BOX' THEN 1 WHEN 'PACK' THEN 2 WHEN 'PKG' THEN 3"
        " WHEN 'BAG' THEN 4 WHEN 'JAR' THEN 5 WHEN 'CAN' THEN 6 WHEN 'DRUM' THEN 7 END),"
        // l_quantity, p_size (integers)
        "l.l_quantity::int,"
        "p.p_size::int,"
        // l_shipmode encoding
        "CASE l.l_shipmode"
        " WHEN 'MAIL' THEN 0 WHEN 'SHIP' THEN 1 WHEN 'RAIL' THEN 2"
        " WHEN 'AIR' THEN 3 WHEN 'TRUCK' THEN 4 WHEN 'AIR REG' THEN 5 WHEN 'FOB' THEN 6 END,"
        // l_shipinstruct encoding
        "CASE l.l_shipinstruct"
        " WHEN 'DELIVER IN PERSON' THEN 0 WHEN 'COLLECT COD' THEN 1"
        " WHEN 'NONE' THEN 2 WHEN 'TAKE BACK RETURN' THEN 3 END,"
        // group key (scalar) + revenue
        "1::bigint,"
        "ROUND(l_extendedprice*(1-l_discount)*100)::bigint "
        "FROM lineitem l JOIN part p ON l.l_partkey = p.p_partkey "
        "ORDER BY l.l_orderkey, l.l_linenumber", 8);
    ASSERT_GT(data.row_count, 0u);

    // Column indices: 0=brand, 1=container, 2=qty, 3=psize, 4=mode, 5=instruct

    // Common thresholds
    const int64_t T_instruct = 0;       // DELIVER IN PERSON
    const int64_t T_mode_air    = 3;    // AIR
    const int64_t T_mode_airreg = 5;    // AIR REG
    const int64_t T_psize_ge = 1;

    // Group 0: Brand#41=15, SM {0,1,2,3}, qty [2,12], psize<=5
    const int64_t T_b0 = 15;
    const std::vector<int64_t> T_c0 = {0, 1, 2, 3};
    const int64_t T_qge0 = 2, T_qle0 = 12, T_ple0 = 5;

    // Group 1: Brand#13=2, MED {12,9,11,10}, qty [14,24], psize<=10
    const int64_t T_b1 = 2;
    const std::vector<int64_t> T_c1 = {12, 9, 11, 10};
    const int64_t T_qge1 = 14, T_qle1 = 24, T_ple1 = 10;

    // Group 2: Brand#55=24, LG {16,17,18,19}, qty [23,33], psize<=15
    const int64_t T_b2 = 24;
    const std::vector<int64_t> T_c2 = {16, 17, 18, 19};
    const int64_t T_qge2 = 23, T_qle2 = 33, T_ple2 = 15;

    // ── Encrypt all thresholds ──────────────────────────────────
    auto tc_inst = encryptThresholdDigits(T_instruct, 4, 1);
    auto tc_ma   = encryptThresholdDigits(T_mode_air, 4, 2);
    auto tc_mar  = encryptThresholdDigits(T_mode_airreg, 4, 2);
    auto tc_psge = encryptThresholdDigits(T_psize_ge, 4, 3);
    std::vector<std::vector<BfvCt>> in_modes = {tc_ma, tc_mar};

    // Group 0
    auto tc_b0 = encryptThresholdDigits(T_b0, 5, 2);
    std::vector<std::vector<BfvCt>> tc_c0;
    for (auto v : T_c0) tc_c0.push_back(encryptThresholdDigits(v, 4, 3));
    auto tc_qge0 = encryptThresholdDigits(T_qge0, 4, 3);
    auto tc_qle0 = encryptThresholdDigits(T_qle0, 4, 3);
    auto tc_ple0 = encryptThresholdDigits(T_ple0, 4, 3);

    // Group 1
    auto tc_b1 = encryptThresholdDigits(T_b1, 5, 2);
    std::vector<std::vector<BfvCt>> tc_c1;
    for (auto v : T_c1) tc_c1.push_back(encryptThresholdDigits(v, 4, 3));
    auto tc_qge1 = encryptThresholdDigits(T_qge1, 4, 3);
    auto tc_qle1 = encryptThresholdDigits(T_qle1, 4, 3);
    auto tc_ple1 = encryptThresholdDigits(T_ple1, 4, 3);

    // Group 2
    auto tc_b2 = encryptThresholdDigits(T_b2, 5, 2);
    std::vector<std::vector<BfvCt>> tc_c2;
    for (auto v : T_c2) tc_c2.push_back(encryptThresholdDigits(v, 4, 3));
    auto tc_qge2 = encryptThresholdDigits(T_qge2, 4, 3);
    auto tc_qle2 = encryptThresholdDigits(T_qle2, 4, 3);
    auto tc_ple2 = encryptThresholdDigits(T_ple2, 4, 3);

    std::map<std::string, size_t> agg_value_cols = {{"revenue", 7}};
    std::vector<AggSpec> agg_specs = {
        {AggType::SUM, "revenue", "revenue"},
    };

    runFilterAggregateTest(data,
        [&](size_t off, size_t rows, size_t ps) {
            auto vb = chunkSlice(data.columns[0], off, rows);  // brand
            auto vc = chunkSlice(data.columns[1], off, rows);  // container
            auto vq = chunkSlice(data.columns[2], off, rows);  // quantity
            auto vp = chunkSlice(data.columns[3], off, rows);  // p_size
            auto vm = chunkSlice(data.columns[4], off, rows);  // shipmode
            auto vi = chunkSlice(data.columns[5], off, rows);  // shipinstruct

            // Common: instruct AND mode_in AND psize_ge
            auto p_inst  = runComparison(vaultdb::GpuCompareOp::EQUAL, tc_inst, vi, ps, 4, 1);
            auto p_mode  = runInPredicate(in_modes, vm, ps, 4, 2);
            auto p_psge  = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_psge, vp, ps, 4, 3);
            auto common1 = gpuAnd(p_inst, p_mode);
            auto common  = gpuAnd(common1, p_psge);

            // Group 0
            auto g0_brand  = runComparison(vaultdb::GpuCompareOp::EQUAL, tc_b0, vb, ps, 5, 2);
            auto g0_cont   = runInPredicate(tc_c0, vc, ps, 4, 3);
            auto g0_qge    = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_qge0, vq, ps, 4, 3);
            auto g0_qle    = runComparison(vaultdb::GpuCompareOp::LESS_EQUAL, tc_qle0, vq, ps, 4, 3);
            auto g0_ple    = runComparison(vaultdb::GpuCompareOp::LESS_EQUAL, tc_ple0, vp, ps, 4, 3);
            auto g0a = gpuAnd(g0_brand, g0_cont);
            auto g0b = gpuAnd(g0_qge, g0_qle);
            auto g0c = gpuAnd(g0a, g0b);
            auto g0  = gpuAnd(g0c, g0_ple);

            // Group 1
            auto g1_brand  = runComparison(vaultdb::GpuCompareOp::EQUAL, tc_b1, vb, ps, 5, 2);
            auto g1_cont   = runInPredicate(tc_c1, vc, ps, 4, 3);
            auto g1_qge    = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_qge1, vq, ps, 4, 3);
            auto g1_qle    = runComparison(vaultdb::GpuCompareOp::LESS_EQUAL, tc_qle1, vq, ps, 4, 3);
            auto g1_ple    = runComparison(vaultdb::GpuCompareOp::LESS_EQUAL, tc_ple1, vp, ps, 4, 3);
            auto g1a = gpuAnd(g1_brand, g1_cont);
            auto g1b = gpuAnd(g1_qge, g1_qle);
            auto g1c = gpuAnd(g1a, g1b);
            auto g1  = gpuAnd(g1c, g1_ple);

            // Group 2
            auto g2_brand  = runComparison(vaultdb::GpuCompareOp::EQUAL, tc_b2, vb, ps, 5, 2);
            auto g2_cont   = runInPredicate(tc_c2, vc, ps, 4, 3);
            auto g2_qge    = runComparison(vaultdb::GpuCompareOp::GREATER_EQUAL, tc_qge2, vq, ps, 4, 3);
            auto g2_qle    = runComparison(vaultdb::GpuCompareOp::LESS_EQUAL, tc_qle2, vq, ps, 4, 3);
            auto g2_ple    = runComparison(vaultdb::GpuCompareOp::LESS_EQUAL, tc_ple2, vp, ps, 4, 3);
            auto g2a = gpuAnd(g2_brand, g2_cont);
            auto g2b = gpuAnd(g2_qge, g2_qle);
            auto g2c = gpuAnd(g2a, g2b);
            auto g2  = gpuAnd(g2c, g2_ple);

            // OR groups, then AND with common
            auto or_groups = gpuOr(g0, g1);
            or_groups = gpuOr(or_groups, g2);
            return gpuAnd(common, or_groups);
        },
        [&](size_t i) -> int64_t {
            auto brand = data.columns[0][i];
            auto cont  = data.columns[1][i];
            auto qty   = data.columns[2][i];
            auto psize = data.columns[3][i];
            auto mode  = data.columns[4][i];
            auto inst  = data.columns[5][i];

            bool cmn = (inst == T_instruct) &&
                       (mode == T_mode_air || mode == T_mode_airreg) &&
                       (psize >= T_psize_ge);
            auto inSet = [](int64_t v, const std::vector<int64_t>& s) {
                for (auto x : s) if (v == x) return true;
                return false;
            };
            bool g0 = brand == T_b0 && inSet(cont, T_c0) && qty >= T_qge0 && qty <= T_qle0 && psize <= T_ple0;
            bool g1 = brand == T_b1 && inSet(cont, T_c1) && qty >= T_qge1 && qty <= T_qle1 && psize <= T_ple1;
            bool g2 = brand == T_b2 && inSet(cont, T_c2) && qty >= T_qge2 && qty <= T_qle2 && psize <= T_ple2;
            return (cmn && (g0 || g1 || g2)) ? 1 : 0;
        },
        6, agg_value_cols, agg_specs, "Q19");
}

// ═══════════════════════════════════════════════════════════════
// main
// ═══════════════════════════════════════════════════════════════

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    ::testing::InitGoogleTest(&argc, argv);

    // Map --filter gflag to gtest filter
    if (!FLAGS_filter.empty())
        ::testing::GTEST_FLAG(filter) = FLAGS_filter;

    std::string log_dir = "log/gpu";
    mkdir("log", 0755);
    mkdir(log_dir.c_str(), 0755);

    std::string log_file = log_dir + "/gpu_fhe_tpch_" + FLAGS_unioned_db + ".log";
    if (gLog.open(log_file)) {
        gLog << "========== gpu_fhe_tpch_test: " << FLAGS_unioned_db
             << " ==========" << std::endl;
        gLog << "Started: " << currentTimestamp() << std::endl;
        gLog << "Crypto mode: HEonGPU (BFV), storage mode: column store" << std::endl;
        gLog << "FHE parameters (BFV / HEonGPU):" << std::endl;
        gLog << "  poly_modulus_degree=" << kPolyModulusDegree
             << " plain_modulus=" << kPlainModulus
             << " mult_depth=" << kMultDepth << std::endl;
        gLog << "  pack_slots=" << (kPolyModulusDegree / 2) << std::endl;
        gLog << std::endl;
    }

    int rc = RUN_ALL_TESTS();

    gLog << std::endl;
    gLog << "========== Done ==========" << std::endl;
    gLog << "Log file: " << log_file << std::endl;
    gLog.flush();

    return rc;
}
