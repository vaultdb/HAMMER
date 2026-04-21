#include "util/fhe/fhe_mpc_party_a.h"

#include <algorithm>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

#include <boost/algorithm/string/trim.hpp>
#include <gtest/gtest.h>

#include "openfhe.h"
#include "util/dictionary_manager.h"
#include "query_table/columnar/fhe_column_table.h"
#include "query_table/field/field_type.h"
#include "query_table/query_table.h"
#include "util/crypto_manager/fhe_manager.h"
#include "util/data_utilities.h"
#include "util/fhe/fhe_helpers.h"
#include "util/fhe/fhe_network.h"
#include "util/google_test_flags.h"

namespace vaultdb {
namespace {
constexpr double kDecimalDisplayScale = 1000000.0;

std::string formatScaledDecimalValue(int64_t scaled_value) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6)
        << (static_cast<double>(scaled_value) / kDecimalDisplayScale);
    std::string s = oss.str();
    auto dot_pos = s.find('.');
    if (dot_pos != std::string::npos) {
        while (!s.empty() && s.back() == '0') s.pop_back();
        if (!s.empty() && s.back() == '.') s.pop_back();
    }
    if (s.empty()) return "0";
    return s;
}

bool isScaledDecimalDisplayColumn(const std::string& field_name, FieldType ft, int col_idx, int group_by_count) {
    if (ft == FieldType::FLOAT) return true;
    if (col_idx < group_by_count) return false;
    return (field_name.find("sum_") == 0) ||
           (field_name.find("avg_") == 0) ||
           (field_name == "revenue");
}

bool isDateDisplayColumn(const std::string& field_name, FieldType ft) {
    return ft == FieldType::DATE || field_name.find("date") != std::string::npos;
}

// Convert FHE-encoded date (days since 1992-01-01) to epoch seconds (since 1970-01-01).
// 1970-01-01 to 1992-01-01 = 22 years, 5 leap years (72,76,80,84,88) = 8035 days.
int64_t relativeDaysToEpochSeconds(int64_t relative_days) {
    constexpr int64_t kEpoch1992Seconds = 8035LL * 86400LL;  // 694224000
    return kEpoch1992Seconds + relative_days * 86400LL;
}

std::string relativeDaysToDateString(int64_t relative_days) {
    // TPC-H date encoding uses days relative to 1992-01-01.
    std::tm base{};
    base.tm_year = 1992 - 1900;
    base.tm_mon = 0;
    base.tm_mday = 1;
    base.tm_hour = 0;
    base.tm_min = 0;
    base.tm_sec = 0;
    base.tm_isdst = -1;
    std::time_t base_t = std::mktime(&base);
    if (base_t == static_cast<std::time_t>(-1)) {
        return std::to_string(relative_days);
    }
    std::time_t target = base_t + static_cast<std::time_t>(relative_days) * 24 * 3600;
    std::tm out{};
#if defined(_WIN32)
    localtime_s(&out, &target);
#else
    localtime_r(&target, &out);
#endif
    char buf[11];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d", &out) == 0) {
        return std::to_string(relative_days);
    }
    return std::string(buf);
}
} // namespace

void ValidateTpchPartyAResults(
    const std::shared_ptr<FheColumnTable>& result_table,
    const std::string& unioned_db,
    const std::string& expected_query) {
    PlainTable* expected_table = DataUtilities::getExpectedResults(unioned_db, expected_query, false, 0);
    if (!expected_table) {
        throw std::runtime_error("[FheTpchTest] Party A: Failed to get expected results");
    }

    FheManager& fhe_manager = FheManager::getInstance();
    const auto& moduli = fhe_manager.getRnsModuli();

    const auto& schema = result_table->getSchema();
    int count_col_idx = schema.getFieldCount() - 1;
    std::string count_col_name = schema.getField(count_col_idx).getName();

    auto enc_col = result_table->getFheColumn(count_col_name);
    if (!enc_col) {
        delete expected_table;
        throw std::runtime_error("[FheTpchTest] Party A: Encrypted column not found: " + count_col_name);
    }

    std::vector<int64_t> actual_values;
    size_t rns_level = enc_col->getRnsLevel();

    for (const auto& chunk : enc_col->getFheChunks()) {
        if (!chunk) continue;
        size_t slot_count = static_cast<size_t>(chunk->packed_count);
        if (slot_count == 0) continue;

        std::vector<std::vector<int64_t>> per_slot_rns_values(slot_count);

        if (rns_level > 1) {
            for (size_t ch = 0; ch < rns_level; ++ch) {
                auto ct = chunk->getCiphertext(ch);
                if (!ct) continue;
                auto cc_ch = fhe_manager.getRnsContext(ch);
                auto sk_ch = fhe_manager.getRnsKeyPair(ch).secretKey;

                lbcrypto::Plaintext pt;
                cc_ch->Decrypt(sk_ch, ct, &pt);
                auto packed = pt->GetPackedValue();

                for (size_t s = 0; s < slot_count && s < packed.size(); ++s) {
                    if (per_slot_rns_values[s].empty()) per_slot_rns_values[s].resize(rns_level);
                    per_slot_rns_values[s][ch] = static_cast<int64_t>(packed[s]);
                }
            }

            std::vector<uint64_t> moduli_use(moduli.begin(), moduli.begin() + static_cast<ptrdiff_t>(rns_level));

            if (FLAGS_debug) {
                std::cout << "\n===== [DEBUG: RNS Channel Values] =====" << std::endl;
                for (size_t s = 0; s < slot_count; ++s) {
                    if (s >= 5) break;
                    if (per_slot_rns_values[s].size() != rns_level) continue;
                    std::cout << "Slot " << s << ": [ ";
                    bool all_same = true;
                    int64_t first_val = per_slot_rns_values[s][0];
                    for (size_t ch = 0; ch < rns_level; ++ch) {
                        int64_t v = per_slot_rns_values[s][ch];
                        std::cout << v << " ";
                        if (v != first_val) all_same = false;
                    }
                    std::cout << "]";
                    if (all_same) {
                        std::cout << " -> All Match! (Valid Small Number: " << first_val << ")";
                    } else {
                        std::cout << " -> Mismatch! (Large Number or Overflow)";
                    }
                    std::cout << " (Moduli: ";
                    for (auto m : moduli_use) std::cout << m << " ";
                    std::cout << ")" << std::endl;
                }
                std::cout << "=======================================\n" << std::endl;
            }

            for (size_t s = 0; s < slot_count; ++s) {
                if (per_slot_rns_values[s].size() != rns_level) {
                    actual_values.push_back(0);
                    continue;
                }
                std::vector<uint64_t> residues(rns_level);
                for (size_t ch = 0; ch < rns_level; ++ch) {
                    int64_t v = per_slot_rns_values[s][ch];
                    uint64_t m = moduli_use[ch];
                    residues[ch] = static_cast<uint64_t>(v < 0 ? (v + static_cast<int64_t>(m)) : v) % m;
                }
                actual_values.push_back(CrtCombine(residues, moduli_use));
            }
        } else {
            auto cc_comp = fhe_manager.getComparisonCryptoContext();
            auto sk_comp = fhe_manager.getComparisonSecretKey();
            if (!cc_comp || !sk_comp) {
                delete expected_table;
                throw std::runtime_error("[FheTpchTest] Party A: Comparison context/secret key unavailable");
            }
            lbcrypto::Plaintext pt;
            cc_comp->Decrypt(sk_comp, chunk->getCiphertext(), &pt);
            auto packed = pt->GetPackedValue();
            size_t take = std::min(packed.size(), static_cast<size_t>(chunk->packed_count));
            for (size_t i = 0; i < take; ++i) {
                actual_values.push_back(static_cast<int64_t>(packed[i]));
            }
        }
    }

    std::vector<int64_t> expected_values;
    int expected_count_col_idx = expected_table->getSchema().getFieldCount() - 1;
    for (int i = 0; i < expected_table->getTrueTupleCount(); ++i) {
        PlainField count_field = expected_table->getField(i, expected_count_col_idx);
        int64_t count_value = getInt64FromField(count_field);
        expected_values.push_back(count_value);
    }

    if (FLAGS_debug) {
        std::cout << "[FheTpchTest] Party A: Actual Values (" << actual_values.size() << "): ";
        for (size_t i = 0; i < std::min(actual_values.size(), static_cast<size_t>(10)); ++i) std::cout << actual_values[i] << " ";
        std::cout << "..." << std::endl;
    }

    if (actual_values.size() != expected_values.size()) {
        std::cout << "[FheTpchTest] FAIL: Size mismatch. Expected " << expected_values.size()
                  << ", Got " << actual_values.size() << std::endl;
        delete expected_table;
        FAIL() << "Group count mismatch";
    }

    std::vector<int64_t> sorted_expected = expected_values;
    std::vector<int64_t> sorted_actual = actual_values;
    std::sort(sorted_expected.begin(), sorted_expected.end());
    std::sort(sorted_actual.begin(), sorted_actual.end());

    if (sorted_expected != sorted_actual) {
        std::cout << "[FheTpchTest] FAIL: Values mismatch!" << std::endl;
        for (size_t i = 0; i < sorted_actual.size(); ++i) {
            if (sorted_actual[i] != sorted_expected[i]) {
                std::cout << "Diff at " << i << ": expected=" << sorted_expected[i]
                          << ", actual=" << sorted_actual[i] << std::endl;
                break;
            }
        }
        delete expected_table;
        FAIL() << "Values mismatch";
    } else {
        std::cout << "[FheTpchTest] PASS: Results match!" << std::endl;
    }

    delete expected_table;
}

void ValidateTpchPartyAResultsFromRowData(const MpcReconstructedRowData* data,
                                          const std::string& unioned_db,
                                          const std::string& expected_query,
                                          int sort_col_cnt,
                                          bool is_mpc_result) {
    if (!data) {
        FAIL() << "[Party A] ValidateTpchPartyAResultsFromRowData: data is null";
    }
    PlainTable* expected = DataUtilities::getExpectedResults(unioned_db, expected_query, false, sort_col_cnt);
    if (!expected) {
        throw std::runtime_error("[Party A] Failed to get expected results from database");
    }
    const size_t row_count = data->row_count;
    const int field_count = data->field_count;
    const std::vector<int64_t>& values = data->values;
    int expected_rows = expected->getTrueTupleCount();
    int expected_cols = expected->getSchema().getFieldCount();

    // Exclude dummy_tag (and legacy __row_dummy__) from comparison; use it for filtering only.
    std::set<int> internal_col_set;
    for (int c = 0; c < field_count; ++c) {
        const std::string& name = data->field_names[static_cast<size_t>(c)];
        if (name == "dummy_tag" || name == "__row_dummy__") {
            internal_col_set.insert(c);
            break;
        }
    }
    const int comparison_field_count = field_count - static_cast<int>(internal_col_set.size());

    std::vector<int> comp_to_actual;
    for (int c = 0; c < field_count; ++c) {
        if (internal_col_set.find(c) == internal_col_set.end()) {
            comp_to_actual.push_back(c);
        }
    }

    if (comparison_field_count != expected_cols) {
        delete expected;
        FAIL() << "[Party A] Column count mismatch: expected " << expected_cols
               << ", got " << field_count << " (internal=" << internal_col_set.size()
               << ", comparison=" << comparison_field_count << ")";
    }

    auto& dm = DictionaryManager::getInstance();

    std::set<int> skip_compare;
    for (int c = 0; c < comparison_field_count; ++c) {
        int actual_c = comp_to_actual[static_cast<size_t>(c)];
        FieldType ft = expected->getSchema().getField(c).getType();
        if (ft != FieldType::STRING) continue;
        std::string col_name = data->field_names[static_cast<size_t>(actual_c)];
        std::string table_name = (static_cast<size_t>(actual_c) < data->table_names.size() &&
                                  !data->table_names[static_cast<size_t>(actual_c)].empty())
            ? data->table_names[static_cast<size_t>(actual_c)] : "";
        if (table_name.empty() || dm.getColumnType(table_name, col_name) == DictColumnType::UNKNOWN) {
            std::string fallback = dm.getTableForColumn(col_name);
            if (!fallback.empty()) table_name = fallback;
        }
        if (table_name.empty() || dm.getColumnType(table_name, col_name) != DictColumnType::ENUM)
            skip_compare.insert(c);
    }

    auto resolveTableName = [&](int col_idx, const std::string& col_name) -> std::string {
        std::string table_name = (static_cast<size_t>(col_idx) < data->table_names.size() &&
                                  !data->table_names[static_cast<size_t>(col_idx)].empty())
            ? data->table_names[static_cast<size_t>(col_idx)] : "";
        if (table_name.empty() || dm.getColumnType(table_name, col_name) == DictColumnType::UNKNOWN) {
            std::string fallback = dm.getTableForColumn(col_name);
            if (!fallback.empty()) table_name = fallback;
        }
        return table_name;
    };

    // Helper: convert expected PlainField to int64 (handles enum via DictionaryManager)
    auto expectedFieldToInt64 = [&](const PlainField& ef, FieldType ft, int col_idx) -> int64_t {
        switch (ft) {
            case FieldType::INT: return static_cast<int64_t>(ef.getValue<int32_t>());
            case FieldType::LONG:
            case FieldType::DATE: return ef.getValue<int64_t>();
            case FieldType::BOOL: return ef.getValue<bool>() ? 1 : 0;
            case FieldType::FLOAT: return static_cast<int64_t>(std::llround(static_cast<double>(ef.getValue<float>()) * 1000000.0));
            case FieldType::STRING: {
                std::string col_name = data->field_names[static_cast<size_t>(col_idx)];
                std::string table_name = resolveTableName(col_idx, col_name);
                if (!table_name.empty() && dm.getColumnType(table_name, col_name) == DictColumnType::ENUM) {
                    std::string str_val = ef.getString();
                    boost::algorithm::trim(str_val);
                    return static_cast<int64_t>(dm.lookupId(table_name, col_name, str_val));
                }
                return 0;  // STRING non-enum: skip comparison
            }
            default: throw std::runtime_error("[Party A] Unsupported expected field type");
        }
    };

    // Plan may sort differently than expected SQL; sort actual/expected independently
    // by full-row keys, then compare in canonical order.
    using Row = std::vector<int64_t>;
    using FloatRow = std::vector<float>;
    std::vector<Row> actual_rows;
    actual_rows.reserve(row_count);
    std::vector<std::pair<Row, FloatRow>> expected_pairs;
    expected_pairs.reserve(static_cast<size_t>(expected_rows));
    for (size_t r = 0; r < row_count; ++r) {
        Row arow;
        for (int c = 0; c < field_count; ++c) {
            arow.push_back(values[static_cast<size_t>(c) * row_count + r]);
        }
        actual_rows.push_back(std::move(arow));
    }
    for (int r = 0; r < expected_rows; ++r) {
        Row erow;
        FloatRow efloat_row(static_cast<size_t>(comparison_field_count), 0.f);
        for (int c = 0; c < comparison_field_count; ++c) {
            int actual_c = comp_to_actual[static_cast<size_t>(c)];
            PlainField ef = expected->getField(r, c);
            FieldType ft = expected->getSchema().getField(c).getType();
            erow.push_back(expectedFieldToInt64(ef, ft, actual_c));
            if (ft == FieldType::FLOAT) efloat_row[static_cast<size_t>(c)] = ef.getValue<float>();
        }
        expected_pairs.emplace_back(std::move(erow), std::move(efloat_row));
    }

    // FHE-only (B only): 0=dummy, non-zero=valid. MPC (B+C): 1=dummy, 0=valid.
    int dummy_col = -1;
    for (int c = 0; c < field_count; ++c) {
        const std::string& name = data->field_names[static_cast<size_t>(c)];
        if (name == "count_order" || name == "dummy_tag" || name == "__row_dummy__") {
            dummy_col = c;
            break;
        }
    }
    if (FLAGS_debug) {
        std::cout << "[Party A][DummyCheck] dummy_col=" << (dummy_col >= 0 ? data->field_names[static_cast<size_t>(dummy_col)] : "none")
                  << ", is_mpc=" << (is_mpc_result ? "yes" : "no")
                  << ", row_count_before_filter=" << actual_rows.size()
                  << std::endl;
    }

    if (dummy_col >= 0) {
        if (FLAGS_debug) {
            size_t sample_cnt = std::min<size_t>(actual_rows.size(), 8);
            std::cout << "[Party A][DummyCheck] sample:";
            for (size_t i = 0; i < sample_cnt; ++i) {
                std::cout << " " << actual_rows[i][static_cast<size_t>(dummy_col)];
            }
            std::cout << std::endl;
        }

        std::vector<Row> filtered_actual_rows;
        filtered_actual_rows.reserve(actual_rows.size());
        size_t filtered_dummy_rows = 0;
        for (const auto& row : actual_rows) {
            int64_t v = row[static_cast<size_t>(dummy_col)];
            // FHE-only (B): 1=valid, 0=dummy. MPC (B+C): 1=dummy, 0=valid (after SCS flip).
            bool is_dummy = is_mpc_result
                ? (v == 1)   // MPC: dummy_tag 1=dummy
                : (v == 0);  // FHE-only: dummy_tag 0=dummy
            if (!is_dummy) {
                filtered_actual_rows.push_back(row);
            } else {
                ++filtered_dummy_rows;
            }
        }
        if (FLAGS_debug) {
            std::cout << "[Party A][DummyCheck] filtered_dummy_rows=" << filtered_dummy_rows
                      << ", row_count_after_filter=" << filtered_actual_rows.size()
                      << std::endl;
        }
        actual_rows.swap(filtered_actual_rows);
    }
    if (!internal_col_set.empty()) {
        for (auto& row : actual_rows) {
            Row stripped;
            stripped.reserve(static_cast<size_t>(comparison_field_count));
            for (int c = 0; c < field_count; ++c) {
                if (internal_col_set.find(c) == internal_col_set.end()) {
                    stripped.push_back(row[static_cast<size_t>(c)]);
                }
            }
            row = std::move(stripped);
        }
    }

    const int key_cols = (sort_col_cnt > 0 && sort_col_cnt <= comparison_field_count) ? sort_col_cnt : comparison_field_count;
    auto keyLessRows = [key_cols](const Row& a, const Row& b) {
        for (int i = 0; i < key_cols; ++i) {
            if (a[static_cast<size_t>(i)] < b[static_cast<size_t>(i)]) return true;
            if (a[static_cast<size_t>(i)] > b[static_cast<size_t>(i)]) return false;
        }
        return a < b;
    };
    std::sort(actual_rows.begin(), actual_rows.end(), keyLessRows);
    std::sort(expected_pairs.begin(), expected_pairs.end(),
              [&keyLessRows](const std::pair<Row, FloatRow>& a, const std::pair<Row, FloatRow>& b) {
                  return keyLessRows(a.first, b.first);
              });

    if (static_cast<int>(actual_rows.size()) != expected_rows) {
        delete expected;
        FAIL() << "[Party A] Row count mismatch after dummy filtering: expected "
               << expected_rows << ", got " << actual_rows.size();
    }

    // Step 5: FLOAT columns store scaled int (M); compare with practical tolerance.
    constexpr float kDecimalScaleFactor = 1000000.0f;
    constexpr float kFloatAbsTolerance = 0.02f;
    constexpr float kFloatRelTolerance = 1e-4f;
    for (size_t r = 0; r < actual_rows.size(); ++r) {
        for (int c = 0; c < comparison_field_count; ++c) {
            if (skip_compare.count(c)) continue;
            int64_t actual_v = actual_rows[r][static_cast<size_t>(c)];
            FieldType ft = expected->getSchema().getField(c).getType();
            if (ft == FieldType::FLOAT) {
                float actual_float = static_cast<float>(actual_v) / kDecimalScaleFactor;
                float expected_float = expected_pairs[r].second[static_cast<size_t>(c)];
                float allowed_tol = std::max(kFloatAbsTolerance, kFloatRelTolerance * std::max(std::fabs(expected_float), 1.0f));
                if (std::abs(actual_float - expected_float) > allowed_tol) {
                    delete expected;
                    FAIL() << "[Party A] Value mismatch row=" << r << " col=" << c
                           << " expected(float)=" << expected_float << " actual(scaled)=" << actual_v
                           << " actual(float)=" << actual_float
                           << " (practical compare, tol=" << allowed_tol << ")";
                }
            } else {
                int64_t expected_v = expected_pairs[r].first[static_cast<size_t>(c)];
                // DATE columns: actual is days since 1992-01-01 (FHE encoding),
                // expected is epoch seconds since 1970-01-01 (PostgreSQL).
                // Use both type check AND name check for robustness (FHE/MPC pipeline
                // may lose DATE type, storing it as LONG).
                int actual_c = comp_to_actual[static_cast<size_t>(c)];
                const std::string& col_name = data->field_names[static_cast<size_t>(actual_c)];
                if (ft == FieldType::DATE || isDateDisplayColumn(col_name, ft)) {
                    actual_v = relativeDaysToEpochSeconds(actual_v);
                }
                if (actual_v != expected_v) {
                    delete expected;
                    FAIL() << "[Party A] Value mismatch row=" << r << " col=" << c
                           << " expected=" << expected_v << " actual=" << actual_v
                           << " col_name=" << col_name << " ft=" << static_cast<int>(ft);
                }
            }
        }
    }
    delete expected;
    std::cout << "[Party A] PASS: MPC result matches expected (ValidateTpchPartyAResultsFromRowData)" << std::endl;
}

std::unique_ptr<MpcReconstructedRowData> ConvertFheTableToRowData(
    const std::shared_ptr<FheColumnTable>& table,
    FheManager& manager) {
    if (!table) {
        throw std::runtime_error("[Party A] ConvertFheTableToRowData: null table");
    }
    auto out = std::make_unique<MpcReconstructedRowData>();
    const auto& schema = table->getSchema();
    out->field_count = schema.getFieldCount();
    if (out->field_count <= 0) {
        return out;
    }

    for (int i = 0; i < out->field_count; ++i) {
        const auto& fd = schema.getField(i);
        out->field_names.push_back(fd.getName());
        out->table_names.push_back(fd.getTableName().empty() ? "" : fd.getTableName());
        out->field_types.push_back(fd.getType());
        out->string_lengths.push_back(static_cast<int>(fd.getStringLength()));
    }

    auto cc = manager.getComparisonCryptoContext();
    auto sk = manager.getComparisonSecretKey();
    if (!cc || !sk) {
        throw std::runtime_error("[Party A] ConvertFheTableToRowData: Comparison context/secret key unavailable");
    }

    std::vector<std::vector<int64_t>> decrypted_cols(static_cast<size_t>(out->field_count));
    size_t total_rows = 0;
    bool debug_rns_printed = false;

    auto plain_snapshot = table->getPlainSnapshot();
    for (int col_idx = 0; col_idx < out->field_count; ++col_idx) {
        const std::string& col_name = out->field_names[static_cast<size_t>(col_idx)];
        if (table->hasEncryptedColumn(col_name)) {
            auto fhe_col = table->getFheColumn(col_name);
            if (!fhe_col) {
                throw std::runtime_error("[Party A] ConvertFheTableToRowData: encrypted column not found: " + col_name);
            }
            const size_t rns_level = fhe_col->getRnsLevel();
            if (FLAGS_debug) std::cout << "[Party A] ConvertFheTableToRowData: column " << col_name << " encrypted rns_level=" << rns_level << std::endl;
            if (rns_level > 1) {
                // Multi-channel RNS (e.g. SUM columns): decrypt each channel, then CRT-combine per slot.
                const auto& moduli = manager.getRnsModuli();
                if (moduli.size() < rns_level) {
                    throw std::runtime_error("[Party A] ConvertFheTableToRowData: RNS moduli size < column rns_level");
                }
                std::vector<uint64_t> moduli_use(moduli.begin(), moduli.begin() + static_cast<ptrdiff_t>(rns_level));
                for (const auto& chunk : fhe_col->getFheChunks()) {
                    if (!chunk) continue;
                    const size_t slot_count = static_cast<size_t>(chunk->packed_count);
                    if (slot_count == 0) continue;
                    std::vector<std::vector<int64_t>> per_channel(slot_count);
                    for (size_t ch = 0; ch < rns_level; ++ch) {
                        auto ct = chunk->getCiphertext(ch);
                        if (!ct) continue;
                        const auto& cc_ch = manager.getRnsContext(ch);
                        const auto& sk_ch = manager.getRnsKeyPair(ch).secretKey;
                        lbcrypto::Plaintext pt_ch;
                        cc_ch->Decrypt(sk_ch, ct, &pt_ch);
                        auto packed_ch = pt_ch->GetPackedValue();
                        for (size_t s = 0; s < slot_count && s < packed_ch.size(); ++s) {
                            if (per_channel[s].size() <= ch)
                                per_channel[s].resize(ch + 1);
                            per_channel[s][ch] = static_cast<int64_t>(packed_ch[s]);
                        }
                    }
                    // [DEBUG] RNS channel values before CRT (first multi-channel column + count_order for debugging)
                    if (FLAGS_debug) {
                        const bool want_debug = !debug_rns_printed || col_name == "count_order";
                        if (want_debug) {
                            if (!debug_rns_printed) debug_rns_printed = true;
                            std::cout << "\n===== [DEBUG: RNS Channel Values] column=" << col_name << " =====\n";
                            for (size_t s = 0; s < slot_count && s < 5; ++s) {
                                if (per_channel[s].size() != rns_level) continue;
                                std::cout << "Slot " << s << ": [ ";
                                bool all_same = true;
                                int64_t first_val = per_channel[s][0];
                                for (size_t ch = 0; ch < rns_level; ++ch) {
                                    int64_t v = per_channel[s][ch];
                                    std::cout << v << " ";
                                    if (v != first_val) all_same = false;
                                }
                                std::cout << "] ";
                                if (all_same) std::cout << "-> All Match! (Small: " << first_val << ")";
                                else std::cout << "-> Mismatch! (Large/Overflow)";
                                std::cout << " (Moduli: ";
                                for (auto m : moduli_use) std::cout << m << " ";
                                std::cout << ")\n";
                            }
                            std::cout << "==========================================\n" << std::endl;
                        }
                    }
                    for (size_t s = 0; s < slot_count; ++s) {
                        if (per_channel[s].size() != rns_level) {
                            decrypted_cols[static_cast<size_t>(col_idx)].push_back(0);
                            continue;
                        }
                        std::vector<uint64_t> residues(rns_level);
                        for (size_t ch = 0; ch < rns_level; ++ch) {
                            int64_t v = per_channel[s][ch];
                            uint64_t m = moduli_use[ch];
                            residues[ch] = static_cast<uint64_t>(v < 0 ? (v + static_cast<int64_t>(m)) : v) % m;
                        }
                        decrypted_cols[static_cast<size_t>(col_idx)].push_back(CrtCombine(residues, moduli_use));
                    }
                }
            } else {
                // Single-channel: decrypt with comparison context (COUNT or legacy single-context).
                for (const auto& chunk : fhe_col->getFheChunks()) {
                    if (!chunk) continue;
                    lbcrypto::Plaintext pt;
                    cc->Decrypt(sk, chunk->getCiphertext(), &pt);
                    auto packed = pt->GetPackedValue();
                    size_t count = std::min(packed.size(), static_cast<size_t>(chunk->packed_count));
                    // [DEBUG] count_order (single-channel) slot values for debugging
                    if (FLAGS_debug && col_name == "count_order") {
                        std::cout << "\n===== [DEBUG: RNS Channel Values] column=" << col_name << " (single-channel) =====\n";
                        for (size_t s = 0; s < count && s < 5; ++s) {
                            std::cout << "Slot " << s << ": " << static_cast<int64_t>(packed[s]) << "\n";
                        }
                        std::cout << "==========================================\n" << std::endl;
                    }
                    for (size_t k = 0; k < count; ++k) {
                        decrypted_cols[static_cast<size_t>(col_idx)].push_back(static_cast<int64_t>(packed[k]));
                    }
                }
            }
        } else if (plain_snapshot) {
            auto plain_col = plain_snapshot->getPlainColumn(col_name);
            if (!plain_col) {
                throw std::runtime_error("[Party A] ConvertFheTableToRowData: column not found (plain or encrypted): " + col_name);
            }
            const auto& fd = schema.getField(col_name);
            for (const auto& chunk : plain_col->getPlainChunks()) {
                if (!chunk) continue;
                for (const auto& f : chunk->getValues()) {
                    int64_t v = 0;
                    switch (fd.getType()) {
                        case FieldType::INT:   v = static_cast<int64_t>(f.getValue<int32_t>()); break;
                        case FieldType::LONG:
                        case FieldType::DATE: v = f.getValue<int64_t>(); break;
                        case FieldType::BOOL:  v = f.getValue<bool>() ? 1 : 0; break;
                        case FieldType::FLOAT: v = static_cast<int64_t>(std::round(static_cast<double>(f.getValue<float_t>()) * 1000000.0)); break;
                        default: v = f.getValue<int64_t>(); break;
                    }
                    decrypted_cols[static_cast<size_t>(col_idx)].push_back(v);
                }
            }
        } else {
            throw std::runtime_error("[Party A] ConvertFheTableToRowData: column not found (no plain snapshot): " + col_name);
        }
    }

    if (!decrypted_cols.empty()) {
        total_rows = decrypted_cols[0].size();
        out->row_count = total_rows;
    }

    out->values.reserve(total_rows * static_cast<size_t>(out->field_count));
    for (int c = 0; c < out->field_count; ++c) {
        const auto& col = decrypted_cols[static_cast<size_t>(c)];
        for (size_t r = 0; r < total_rows; ++r) {
            out->values.push_back(r < col.size() ? col[r] : 0);
        }
    }

    return out;
}

void PrintPartyAResultTable(const MpcReconstructedRowData* data, bool is_mpc_result) {
    if (!data) {
        std::cout << "[Party A] Result table: (null)" << std::endl;
        return;
    }
    const size_t row_count = data->row_count;
    const int field_count = data->field_count;
    auto& dm = DictionaryManager::getInstance();
    auto resolveTableName = [&](int col_idx, const std::string& col_name) -> std::string {
        std::string table_name = (static_cast<size_t>(col_idx) < data->table_names.size() &&
                                  !data->table_names[static_cast<size_t>(col_idx)].empty())
            ? data->table_names[static_cast<size_t>(col_idx)] : "";
        if (table_name.empty() || dm.getColumnType(table_name, col_name) == DictColumnType::UNKNOWN) {
            std::string fallback = dm.getTableForColumn(col_name);
            if (!fallback.empty()) table_name = fallback;
        }
        return table_name;
    };

    // Find dummy_tag (or __row_dummy__) or count_order column for filtering.
    // MPC: dummy_tag holds 0=valid, 1=dummy (from SCS). FHE-only: count/dummy_tag 0=dummy, non-zero=valid.
    int dummy_col = -1;
    for (int c = 0; c < field_count; ++c) {
        const std::string& name = data->field_names[static_cast<size_t>(c)];
        if (name == "dummy_tag" || name == "__row_dummy__" || name == "count_order") {
            dummy_col = c;
            break;
        }
    }

    // Filter rows: MPC: valid = (v==0). FHE-only: valid = (v>0).
    std::vector<std::vector<int64_t>> rows_to_print;
    rows_to_print.reserve(row_count);
    for (size_t r = 0; r < row_count; ++r) {
        std::vector<int64_t> row;
        row.reserve(static_cast<size_t>(field_count));
        for (int c = 0; c < field_count; ++c) {
            size_t idx = static_cast<size_t>(c) * row_count + r;
            row.push_back(data->values[idx]);
        }
        if (dummy_col >= 0) {
            int64_t v = row[static_cast<size_t>(dummy_col)];
            bool is_valid = is_mpc_result ? (v == 0) : (v > 0);
            if (!is_valid) continue;
        }
        rows_to_print.push_back(std::move(row));
    }

    // Hide dummy_tag column from display unless --debug is set
    bool hide_dummy_col = !FLAGS_debug && dummy_col >= 0;
    int display_col_count = hide_dummy_col ? field_count - 1 : field_count;

    std::cout << "[Party A] Result table: " << rows_to_print.size() << " valid rows (of " << row_count << ") x " << display_col_count << " columns" << std::endl;
    std::cout << "Col\t";
    for (int c = 0; c < field_count; ++c) {
        if (hide_dummy_col && c == dummy_col) continue;
        std::cout << data->field_names[static_cast<size_t>(c)] << "\t";
    }
    std::cout << std::endl;
    std::cout << "Type\t";
    for (int c = 0; c < field_count; ++c) {
        if (hide_dummy_col && c == dummy_col) continue;
        FieldType ft = (static_cast<size_t>(c) < data->field_types.size()) ? data->field_types[static_cast<size_t>(c)] : FieldType::LONG;
        const char* name = "?";
        switch (ft) {
            case FieldType::INT: name = "INT"; break;
            case FieldType::LONG: name = "LONG"; break;
            case FieldType::FLOAT: name = "FLOAT"; break;
            case FieldType::BOOL: name = "BOOL"; break;
            case FieldType::DATE: name = "DATE"; break;
            case FieldType::STRING: name = "STR"; break;
            default: name = "?"; break;
        }
        std::cout << name << "\t";
    }
    std::cout << std::endl;
    const size_t print_rows = std::min(rows_to_print.size(), static_cast<size_t>(20));
    for (size_t r = 0; r < print_rows; ++r) {
        std::cout << "r" << r << "\t";
        const std::vector<int64_t>& row = rows_to_print[r];
        for (int c = 0; c < field_count; ++c) {
            if (hide_dummy_col && c == dummy_col) continue;
            int64_t v = row[static_cast<size_t>(c)];
            const std::string& col_name = data->field_names[static_cast<size_t>(c)];
            std::string table_name = resolveTableName(c, col_name);
            FieldType ft = (static_cast<size_t>(c) < data->field_types.size()) ? data->field_types[static_cast<size_t>(c)] : FieldType::LONG;
            if (isDateDisplayColumn(col_name, ft)) {
                std::cout << relativeDaysToDateString(v) << "\t";
            } else if (isScaledDecimalDisplayColumn(col_name, ft, c, 0)) {
                std::cout << formatScaledDecimalValue(v) << "\t";
            } else if (dm.isLoaded() && !table_name.empty() && dm.getColumnType(table_name, col_name) == DictColumnType::ENUM) {
                std::string s = dm.lookupString(table_name, col_name, static_cast<int>(v));
                std::cout << (s.empty() ? std::to_string(v) : s) << "\t";
            } else {
                std::cout << v << "\t";
            }
        }
        std::cout << std::endl;
    }
    if (print_rows < rows_to_print.size()) {
        std::cout << "... (" << (rows_to_print.size() - print_rows) << " more rows)" << std::endl;
    }
    std::cout << std::endl;
}

void DebugTpchPartyAMaskedDecrypt(FheNetworkIO* network_io) {
    if (!network_io) {
        throw std::runtime_error("[FheTpchTest] Party A: Network IO unavailable for debug masked decrypt");
    }

    std::cout << "[FheTpchTest] Party A: Debug receive masked ciphertext from Party B" << std::endl;
    std::string masked_str = network_io->recvString();
    std::istringstream masked_iss(masked_str);
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ct_masked;
    lbcrypto::Serial::Deserialize(ct_masked, masked_iss, lbcrypto::SerType::BINARY);

    FheManager& manager = FheManager::getInstance();
    auto cc_bfv = manager.getBFVCryptoContext();
    auto sk_bfv = manager.getBFVSecretKey();
    if (!cc_bfv || !sk_bfv) {
        throw std::runtime_error("[FheTpchTest] Party A: BFV context/secret key unavailable");
    }

    lbcrypto::Plaintext pt_masked;
    cc_bfv->Decrypt(sk_bfv, ct_masked, &pt_masked);
    const auto values = pt_masked->GetPackedValue();

    size_t count = values.size();
    network_io->sendData(&count, sizeof(size_t));
    if (count > 0) {
        network_io->sendData(values.data(), count * sizeof(int64_t));
    }

    std::cout << "========== [PARTY A DEBUG M+R] ==========" << std::endl;
    std::cout << "Party A Decrypt (M+R): ";
    for (size_t i = 0; i < std::min(static_cast<size_t>(10), values.size()); ++i) {
        std::cout << values[i] << " ";
    }
    std::cout << "\n========================================\n" << std::endl;
}

namespace {
constexpr int kMaxFieldCount = 1024;
constexpr size_t kMaxRowCount = 50 * 1000 * 1000;
constexpr size_t kMaxShareCount = 50 * 1000 * 1000;
}  // namespace

std::unique_ptr<MpcReconstructedRowData> CollectSharesAndReconstruct(FheNetworkIO* bio, FheNetworkIO* cio, bool validation) {
    if (!bio || !cio) {
        throw std::runtime_error("[Party A] CollectSharesAndReconstruct: null network IO");
    }
    if (FLAGS_debug) std::cout << "[Party A] Receiving metadata from B..." << std::endl;
    int field_count_b = 0;
    size_t row_count_b = 0;
    int group_by_count_b = 0;
    bio->recvData(&field_count_b, sizeof(int));
    bio->recvData(&row_count_b, sizeof(size_t));
    bio->recvData(&group_by_count_b, sizeof(int));

    if (field_count_b <= 0 || field_count_b > kMaxFieldCount) {
        throw std::runtime_error("[Party A] Invalid field_count_b=" + std::to_string(field_count_b));
    }
    if (row_count_b > kMaxRowCount) {
        throw std::runtime_error("[Party A] row_count_b too large: " + std::to_string(row_count_b));
    }
    if (group_by_count_b < 0 || group_by_count_b > field_count_b) {
        throw std::runtime_error("[Party A] Invalid group_by_count_b=" + std::to_string(group_by_count_b));
    }

    std::vector<std::string> field_names;
    std::vector<FieldType> field_types;
    std::vector<std::string> table_names;
    std::vector<int> string_lengths;
    field_names.reserve(field_count_b);
    field_types.reserve(field_count_b);
    table_names.reserve(field_count_b);
    string_lengths.reserve(field_count_b);
    for (int i = 0; i < field_count_b; ++i) {
        field_names.push_back(bio->recvString());
        int ft;
        bio->recvData(&ft, sizeof(int));
        field_types.push_back(static_cast<FieldType>(ft));
        table_names.push_back(bio->recvString());
        int sl;
        bio->recvData(&sl, sizeof(int));
        string_lengths.push_back(sl);
    }

    size_t share_count_b = 0;
    bio->recvData(&share_count_b, sizeof(size_t));
    if (share_count_b > kMaxShareCount) {
        throw std::runtime_error("[Party A] share_count_b too large: " + std::to_string(share_count_b));
    }
    std::vector<int64_t> shares_b(share_count_b);
    if (share_count_b > 0) {
        bio->recvData(shares_b.data(), share_count_b * sizeof(int64_t));
    }

    size_t share_count_c = 0;
    cio->recvData(&share_count_c, sizeof(size_t));
    if (share_count_c > kMaxShareCount) {
        throw std::runtime_error("[Party A] share_count_c too large: " + std::to_string(share_count_c));
    }
    std::vector<int64_t> shares_c(share_count_c);
    if (share_count_c > 0) {
        cio->recvData(shares_c.data(), share_count_c * sizeof(int64_t));
    }
    if (FLAGS_debug) std::cout << "[Party A] Received from B and C, reconstructing..." << std::endl;

    if (share_count_b != share_count_c) {
        throw std::runtime_error("[Party A] Share count mismatch B=" + std::to_string(share_count_b) +
                                " C=" + std::to_string(share_count_c));
    }
    // Hand-implemented asymmetric reveal (B,C -> A). Reference: EMP sh_gen.h / sh_eva.h.
    // Our 3-party: B (Generator/Alice) and C (Evaluator/Bob) each send their LOCAL share to A.
    // No B<->C reveal(); A is the sole reconstructor.
    //
    // secretShareAdditive runs a 2PC circuit: val_A + val_B = R + (M-R) = M.
    // The SecureTable stores M in XOR-shared form (garbled wire labels).
    // extractAllLocalShares reads each party's XOR share of M (LSB of wire labels).
    // Reconstruction: M = shares_b XOR shares_c (XOR of the two shares yields the value).
    std::vector<int64_t> final_values(share_count_b);
    for (size_t i = 0; i < share_count_b; ++i) {
        uint64_t u_b = static_cast<uint64_t>(shares_b[i]);
        uint64_t u_c = static_cast<uint64_t>(shares_c[i]);
        final_values[i] = static_cast<int64_t>(u_b ^ u_c);
    }

    auto& dm = DictionaryManager::getInstance();
    auto resolveTableName = [&](int col_idx, const std::string& col_name) -> std::string {
        std::string table_name = (static_cast<size_t>(col_idx) < table_names.size() &&
                                  !table_names[static_cast<size_t>(col_idx)].empty())
            ? table_names[static_cast<size_t>(col_idx)] : "";
        if (table_name.empty() || dm.getColumnType(table_name, col_name) == DictColumnType::UNKNOWN) {
            std::string fallback = dm.getTableForColumn(col_name);
            if (!fallback.empty()) table_name = fallback;
        }
        return table_name;
    };
    auto is_enum_col = [&](int col_idx) -> bool {
        if (col_idx < 0 || static_cast<size_t>(col_idx) >= field_names.size()) return false;
        const std::string& fn = field_names[static_cast<size_t>(col_idx)];
        std::string table_name = (static_cast<size_t>(col_idx) < table_names.size() &&
                                  !table_names[static_cast<size_t>(col_idx)].empty())
            ? table_names[static_cast<size_t>(col_idx)] : dm.getTableForColumn(fn);
        return dm.isLoaded() && !table_name.empty() &&
               dm.getColumnType(table_name, fn) == DictColumnType::ENUM;
    };

    // Aggregate columns (group_by_count_b ..) and enum key columns are normalized to canonical
    // representative in Z_(P_TOTAL) so display/validation are stable across share representations.
    for (int col = group_by_count_b; col < field_count_b; ++col) {
        for (size_t r = 0; r < row_count_b; ++r) {
            size_t idx = static_cast<size_t>(col) * row_count_b + r;
            final_values[idx] = ReduceModPTotal(final_values[idx]);
        }
    }
    for (int col = 0; col < group_by_count_b; ++col) {
        if (!is_enum_col(col)) continue;
        for (size_t r = 0; r < row_count_b; ++r) {
            size_t idx = static_cast<size_t>(col) * row_count_b + r;
            final_values[idx] = ReduceModPTotal(final_values[idx]);
        }
    }

    size_t expected_count = static_cast<size_t>(field_count_b) * row_count_b;
    if (final_values.size() != expected_count) {
        throw std::runtime_error("[Party A] Value count mismatch expected=" + std::to_string(expected_count) +
                                " actual=" + std::to_string(final_values.size()));
    }

    if (!validation) {
        return nullptr;
    }

    auto out = std::make_unique<MpcReconstructedRowData>();
    out->values = std::move(final_values);
    out->field_names = std::move(field_names);
    out->table_names = std::move(table_names);
    out->field_types = std::move(field_types);
    out->string_lengths = std::move(string_lengths);
    out->row_count = row_count_b;
    out->field_count = field_count_b;
    out->group_by_count = group_by_count_b;

    return out;
}
}  // namespace vaultdb
