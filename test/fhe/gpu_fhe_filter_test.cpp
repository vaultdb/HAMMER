// GPU FHE filter benchmark (Q1-style: l_shipdate <= '1998-08-03', base4).
// Standalone test using HEonGPU -- no multi-party setup, no OpenFHE dependency.
//
// Usage:
//   ./bin/gpu_fhe_filter_test
//   ./bin/gpu_fhe_filter_test --unioned_db=tpch_unioned_150
//   ./bin/gpu_fhe_filter_test --unioned_db=tpch_unioned_1500
//   ./bin/gpu_fhe_filter_test --validation=false

#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <pqxx/pqxx>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "gpu_fhe_backend.cuh"
#include "gpu_fhe_comparator.cuh"

DECLARE_string(unioned_db);
DECLARE_bool(validation);

namespace {

std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S%z");
    return oss.str();
}

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

// BFV / HEonGPU (must match SetUpTestSuite GpuBfvParams)
constexpr size_t kPolyModulusDegree = 32768;
constexpr uint64_t kPlainModulus    = 1179649;
constexpr uint32_t kMultDepth       = 8;

constexpr size_t kRadixBase   = 4;
constexpr size_t kNumDigits   = 6;
const char* kThresholdDate    = "1998-08-03";
const char* kBaseDate         = "1992-01-01";

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

struct ShipdateData {
    std::vector<int64_t> values;
    size_t row_count;
};

ShipdateData loadShipdatesFromPostgres(const std::string& db_name) {
    std::string connstr = "user=vaultdb dbname=" + db_name;
    pqxx::connection conn(connstr);
    pqxx::work txn(conn);
    pqxx::result res = txn.exec(
        "SELECT (l_shipdate - DATE '1992-01-01') AS days "
        "FROM lineitem ORDER BY l_orderkey, l_linenumber");
    txn.commit();
    conn.close();

    ShipdateData data;
    data.row_count = res.size();
    data.values.reserve(data.row_count);
    for (const auto& row : res)
        data.values.push_back(row[0].as<int64_t>());
    return data;
}

std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>
encryptThresholdDigits(int64_t threshold, size_t radix_base, size_t num_digits) {
    auto& backend = vaultdb::GpuFheBackend::getInstance();
    auto& ctx     = backend.context();
    auto& encoder = backend.encoder();
    auto& encryptor = backend.encryptor();

    size_t slots = backend.slotCount();
    auto digits = vaultdb::encodeRadix(threshold, radix_base, num_digits);

    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> ciphers;
    ciphers.reserve(num_digits);
    for (size_t i = 0; i < num_digits; ++i) {
        std::vector<int64_t> digit_vec(slots, digits[i]);
        heongpu::Plaintext<heongpu::Scheme::BFV> pt(ctx);
        encoder.encode(pt, digit_vec);
        heongpu::Ciphertext<heongpu::Scheme::BFV> ct(ctx);
        encryptor.encrypt(ct, pt);
        ciphers.push_back(std::move(ct));
    }
    return ciphers;
}

}  // namespace

class GpuFheFilterTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        vaultdb::GpuBfvParams params;
        params.poly_modulus_degree = kPolyModulusDegree;
        params.plain_modulus       = kPlainModulus;
        params.mult_depth          = kMultDepth;

        auto& backend = vaultdb::GpuFheBackend::getInstance();
        if (!backend.isInitialized()) {
            gLog << "[GpuFheFilterTest] Initializing HEonGPU backend..." << std::endl;
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

TEST_F(GpuFheFilterTest, Q1_LessEqual_Base4) {
    using namespace std::chrono;

    auto& backend = vaultdb::GpuFheBackend::getInstance();
    size_t pack_slots = backend.slotCount();

    gLog << "[GpuFheFilterTest] DB=" << FLAGS_unioned_db
         << " | l_shipdate <= " << kThresholdDate << " | base4" << std::endl;

    auto t_load_start = high_resolution_clock::now();
    auto shipdate_data = loadShipdatesFromPostgres(FLAGS_unioned_db);
    auto t_load_end = high_resolution_clock::now();

    size_t row_count = shipdate_data.row_count;
    gLog << "[Timing] Postgres load: "
         << duration_cast<milliseconds>(t_load_end - t_load_start).count()
         << " ms (" << row_count << " rows)" << std::endl;

    ASSERT_GT(row_count, 0) << "No rows loaded from " << FLAGS_unioned_db;

    size_t num_chunks = (row_count + pack_slots - 1) / pack_slots;
    gLog << "[Info] row_count=" << row_count << " pack_slots=" << pack_slots
         << " chunks=" << num_chunks << std::endl;

    int64_t threshold_days = dateToDaysSinceBase(kThresholdDate);
    gLog << "[Info] Threshold '" << kThresholdDate << "' = "
         << threshold_days << " days since " << kBaseDate << std::endl;

    auto t_enc_start = high_resolution_clock::now();
    auto threshold_ciphers = encryptThresholdDigits(threshold_days, kRadixBase, kNumDigits);
    auto t_enc_end = high_resolution_clock::now();
    gLog << "[Timing] Threshold encryption (" << kNumDigits << " digits): "
         << duration_cast<milliseconds>(t_enc_end - t_enc_start).count() << " ms" << std::endl;

    long long total_filter_ms = 0;
    std::vector<std::vector<int64_t>> all_decrypted;

    for (size_t chunk = 0; chunk < num_chunks; ++chunk) {
        size_t offset = chunk * pack_slots;
        size_t chunk_rows = std::min(pack_slots, row_count - offset);

        std::vector<int64_t> chunk_values(
            shipdate_data.values.begin() + offset,
            shipdate_data.values.begin() + offset + chunk_rows);

        auto t_radix_start = high_resolution_clock::now();
        auto radix_columns = vaultdb::buildRadixColumns(
            chunk_values, kRadixBase, kNumDigits, pack_slots);
        auto t_radix_end = high_resolution_clock::now();

        gLog << ">>> Chunk " << chunk << "/" << num_chunks
             << " (" << chunk_rows << " rows) radix: "
             << duration_cast<milliseconds>(t_radix_end - t_radix_start).count()
             << " ms" << std::endl;

        auto t_filter_start = high_resolution_clock::now();
        auto result_ct = vaultdb::gpuPolynomialComparisonLe(
            threshold_ciphers, radix_columns, pack_slots, kRadixBase);
        auto t_filter_end = high_resolution_clock::now();

        auto chunk_filter_ms = duration_cast<milliseconds>(t_filter_end - t_filter_start).count();
        total_filter_ms += chunk_filter_ms;
        gLog << "[Timing] Chunk " << chunk << " GPU filter: "
             << chunk_filter_ms << " ms" << std::endl;

        if (FLAGS_validation) {
            auto& ctx       = backend.context();
            auto& encoder   = backend.encoder();
            auto& decryptor = backend.decryptor();

            heongpu::Plaintext<heongpu::Scheme::BFV> pt_result(ctx);
            decryptor.decrypt(pt_result, result_ct);
            std::vector<int64_t> decrypted(pack_slots);
            encoder.decode(decrypted, pt_result);
            decrypted.resize(chunk_rows);
            all_decrypted.push_back(std::move(decrypted));
        }
    }

    gLog << "[GpuFheFilterTest] GPU Filter total: " << total_filter_ms
         << " ms (" << num_chunks << " chunks)" << std::endl;

    if (FLAGS_validation) {
        size_t match = 0, mismatch = 0, pass_count = 0;
        size_t global_idx = 0;
        for (size_t c = 0; c < num_chunks; ++c) {
            size_t offset = c * pack_slots;
            for (size_t i = 0; i < all_decrypted[c].size(); ++i, ++global_idx) {
                int64_t expected = (shipdate_data.values[offset + i] <= threshold_days) ? 1 : 0;
                int64_t got = all_decrypted[c][i];
                if (expected) ++pass_count;
                if (got == expected) {
                    ++match;
                } else {
                    ++mismatch;
                    if (mismatch <= 10) {
                        gLog << "  Mismatch row " << global_idx << ": expected=" << expected
                             << " got=" << got << " (shipdate=" << shipdate_data.values[offset + i]
                             << ", threshold=" << threshold_days << ")" << std::endl;
                    }
                }
            }
        }
        gLog << "[Validation] " << row_count << " rows: "
             << match << " match, " << mismatch << " mismatch, "
             << pass_count << " pass filter" << std::endl;
        EXPECT_EQ(mismatch, 0) << mismatch << " rows did not match expected indicator";
    }
}

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    ::testing::InitGoogleTest(&argc, argv);

    std::string log_dir = "log/gpu";
    mkdir("log", 0755);
    mkdir(log_dir.c_str(), 0755);

    std::string log_file = log_dir + "/gpu_fhe_filter_" + FLAGS_unioned_db + ".log";
    if (gLog.open(log_file)) {
        gLog << "========== gpu_fhe_filter_test: " << FLAGS_unioned_db << " ==========" << std::endl;
        gLog << "Started: " << currentTimestamp() << std::endl;
        gLog << "Crypto mode: HEonGPU (BFV), storage mode: column store" << std::endl;
        gLog << "GFlags: --unioned_db=" << FLAGS_unioned_db
             << " --validation=" << (FLAGS_validation ? "true" : "false") << std::endl;
        gLog << "FHE parameters (BFV / HEonGPU):" << std::endl;
        gLog << "  poly_modulus_degree=" << kPolyModulusDegree
             << " plain_modulus=" << kPlainModulus
             << " mult_depth=" << kMultDepth << std::endl;
        gLog << "  pack_slots=" << (kPolyModulusDegree / 2)
             << " (SIMD slots per ciphertext)" << std::endl;
        gLog << "  filter: radix_base=" << kRadixBase << " num_digits=" << kNumDigits
             << " l_shipdate<=" << kThresholdDate << std::endl;
        gLog << std::endl;
    } else {
        std::cerr << "[Warning] Could not open log file: " << log_file << std::endl;
    }

    int rc = RUN_ALL_TESTS();

    gLog << std::endl;
    gLog << "========== Done ==========" << std::endl;
    gLog << "Log file: " << log_file << std::endl;
    gLog.flush();

    return rc;
}
