// Single-machine FHE filter benchmark (Q1-style: l_shipdate <= '1998-08-03', base4).
// No multi-party setup required. Use --unioned_db to vary DB size.
//
// Usage:
//   ./bin/fhe_filter_test
//   ./bin/fhe_filter_test --unioned_db=tpch_unioned_150
//   ./bin/fhe_filter_test --unioned_db=tpch_unioned_1500
//   ./bin/fhe_filter_test --unioned_db=tpch_unioned_15000
//   ./bin/fhe_filter_test --validation=false   # faster, no reveal
//   ./bin/fhe_filter_test --filter='*Polynomial*'  # run only Polynomial (quote needed)
#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <util/type_utilities.h>
#include <util/utilities.h>
#include <stdexcept>
#include <operators/columnar/fhe_sql_input.h>
#include <operators/columnar/fhe_filter.h>
#include <operators/columnar/column_operator.h>
#include <query_table/columnar/fhe_column_table.h>
#include <util/data_utilities.h>
#include "openfhe.h"
#include <test/fhe/fhe_base_test.h>
#include <util/crypto_manager/fhe_manager.h>
#include <util/dictionary_manager.h>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <iomanip>

using namespace lbcrypto;
using namespace vaultdb;

namespace {
constexpr size_t kBase4Radix = 4;
constexpr size_t kBase4NumDigits = 6;
const char* kQ1PredicateDate = "1998-08-03";

int64_t relativeDaysFromDateString(const std::string& date_str) {
    static const std::string base_date = "1992-01-01";
    auto parse_date = [](const std::string& str) {
        std::tm t{};
        int y, m, d;
        if (std::sscanf(str.c_str(), "%d-%d-%d", &y, &m, &d) != 3) {
            throw std::runtime_error("Failed to parse date string: " + str);
        }
        t.tm_year = y - 1900;
        t.tm_mon = m - 1;
        t.tm_mday = d;
        t.tm_hour = t.tm_min = t.tm_sec = 0;
        t.tm_isdst = -1;
        return t;
    };
    std::tm base_tm = parse_date(base_date);
    std::tm curr_tm = parse_date(date_str);
    const int64_t base_days = static_cast<int64_t>(mktime(&base_tm) / (24 * 3600));
    const int64_t current_days = static_cast<int64_t>(mktime(&curr_tm) / (24 * 3600));
    return current_days - base_days;
}

std::vector<int64_t> collectColumnValues(const PlainColumnTable& table, const std::string& column_name) {
    auto column = table.getPlainColumn(column_name);
    if (!column) throw std::runtime_error("Column not found: " + column_name);
    std::vector<int64_t> values;
    for (const auto& chunk : column->getPlainChunks()) {
        if (!chunk) continue;
        for (const auto& field : chunk->getValues()) {
            switch (field.getType()) {
                case FieldType::INT: values.push_back(static_cast<int64_t>(field.getValue<int32_t>())); break;
                case FieldType::LONG:
                case FieldType::DATE: values.push_back(field.getValue<int64_t>()); break;
                default: throw std::runtime_error("Unsupported type in collectColumnValues");
            }
        }
    }
    values.resize(table.getRowCount());
    return values;
}

std::vector<int64_t> decryptIndicator(const std::shared_ptr<FheColumnTable>& table, size_t row_count) {
    auto indicator_col = table->getDummyTagColumn();
    if (!indicator_col) throw std::runtime_error("Indicator column is not set");
    FheManager& manager = FheManager::getInstance();
    auto cc = manager.getComparisonCryptoContext();
    auto sk = manager.getComparisonSecretKey();
    if (!cc || !sk) throw std::runtime_error("Comparison crypto context unavailable");
    std::vector<int64_t> indicator_values;
    indicator_values.reserve(row_count);
    for (const auto& chunk : indicator_col->getFheChunks()) {
        lbcrypto::Plaintext pt;
        cc->Decrypt(sk, chunk->getCiphertext(), &pt);
        const auto packed = pt->GetPackedValue();
        size_t count = std::min(static_cast<size_t>(packed.size()), chunk->packed_count);
        indicator_values.insert(indicator_values.end(), packed.begin(), packed.begin() + count);
    }
    indicator_values.resize(row_count);
    // FHE convention: 1=valid (satisfied), 0=dummy; return as-is for comparison with expected_flags
    return indicator_values;
}

std::vector<int64_t> encodeRadixDigits(int64_t value, size_t base, size_t digits) {
    std::vector<int64_t> encoded(digits, 0);
    int64_t current = value;
    for (size_t i = 0; i < digits; ++i) {
        encoded[i] = current % static_cast<int64_t>(base);
        current /= static_cast<int64_t>(base);
    }
    return encoded;
}

std::vector<Ciphertext<DCRTPoly>> encryptRadixDigits(int64_t threshold, size_t radix_base, size_t num_digits) {
    FheManager& manager = FheManager::getInstance();
    auto cc = manager.getComparisonCryptoContext();
    auto pk = manager.getComparisonPublicKey();
    if (!cc || !pk) throw std::runtime_error("encryptRadixDigits: comparison crypto context unavailable");
    auto digits = encodeRadixDigits(threshold, radix_base, num_digits);
    size_t pack_slots = manager.getBFVComparisonBatchSize();
    std::vector<Ciphertext<DCRTPoly>> digit_ciphers(num_digits);
    for (size_t i = 0; i < num_digits; ++i) {
        std::vector<int64_t> digit_vec(pack_slots, digits[i]);
        Plaintext plain = cc->MakePackedPlaintext(digit_vec);
        digit_ciphers[i] = cc->Encrypt(pk, plain);
    }
    return digit_ciphers;
}

std::string buildSql() {
    return FLAGS_cutoff == -1
        ? "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem ORDER BY (1), (2)"
        : "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem WHERE l_orderkey <= "
          + std::to_string(FLAGS_cutoff) + " ORDER BY (1), (2)";
}
}  // namespace

class FheFilterTest : public FheBaseTest {
protected:
    void SetUp() override {
        FheBaseTest::SetUp();
        std::string dict_path = Utilities::getCurrentWorkingDirectory() + "/conf/plans/fhe/tpch_metadata_dictionary_base4.json";
        DictionaryManager::getInstance().load(dict_path);
    }

    void prepareData(std::shared_ptr<FheColumnTable>& base_table,
                     int64_t& threshold_relative,
                     size_t& row_count,
                     std::vector<int64_t>& expected_flags,
                     std::vector<Ciphertext<DCRTPoly>>& threshold_digits) {
        std::string sql = buildSql();
        SortDefinition collation = DataUtilities::getDefaultSortDefinition(2);
        std::vector<int32_t> group_by_ordinals = {0, 1};

        std::cout << "[FheFilterTest] DB=" << db_name_ << " | l_shipdate <= " << kQ1PredicateDate << " | base4" << std::endl;
        std::cout << "[Query] " << sql << std::endl;

        auto t1 = std::chrono::high_resolution_clock::now();
        FheSqlInput input(db_name_, sql, collation, 0, 0, true, group_by_ordinals);
        auto base_output_table = input.runSelf();
        auto t2 = std::chrono::high_resolution_clock::now();
        std::cout << "[Timing] FheSqlInput: " << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << " ms" << std::endl;

        ASSERT_NE(nullptr, base_output_table);
        base_table = std::dynamic_pointer_cast<FheColumnTable>(base_output_table);
        ASSERT_NE(nullptr, base_table);
        ASSERT_GT(base_table->getRowCount(), 0);

        auto plain_snapshot = base_table->getPlainSnapshot();
        ASSERT_NE(nullptr, plain_snapshot);
        row_count = plain_snapshot->getRowCount();
        threshold_relative = relativeDaysFromDateString(kQ1PredicateDate);

        if (FLAGS_validation) {
            auto shipdates = collectColumnValues(*plain_snapshot, "l_shipdate");
            shipdates.resize(row_count);
            expected_flags.resize(row_count);
            for (size_t i = 0; i < row_count; ++i)
                expected_flags[i] = (shipdates[i] <= threshold_relative) ? 1 : 0;
        }

        threshold_digits = encryptRadixDigits(threshold_relative, kBase4Radix, kBase4NumDigits);
    }
};

TEST_F(FheFilterTest, Benchmark_PolynomialStyle) {
    using namespace std::chrono;
    std::shared_ptr<FheColumnTable> base_table;
    int64_t threshold;
    size_t row_count;
    std::vector<int64_t> expected_flags;
    std::vector<Ciphertext<DCRTPoly>> threshold_digits;

    prepareData(base_table, threshold, row_count, expected_flags, threshold_digits);

    std::cout << ">>> Polynomial Style (base4)..." << std::endl;
    resetComparisonStats();
    auto poly_pred = makePolynomialLessEqualPredicate(base_table->getSchema(), "l_shipdate", threshold_digits, kBase4Radix);

    // Use base_table directly to avoid second table scan (FheFilter accepts shared_ptr<FheColumnTable>)
    auto start = high_resolution_clock::now();
    FheFilter poly_filter(base_table, {poly_pred});
    poly_filter.setOperatorId(1);
    auto output = std::dynamic_pointer_cast<FheColumnTable>(poly_filter.runSelf());
    auto end = high_resolution_clock::now();

    auto duration_ms = duration_cast<milliseconds>(end - start).count();
    std::cout << "[FheFilterTest] Polynomial: Filter time " << duration_ms << " ms" << std::endl;
    auto stats = getPolynomialComparisonStats();
    std::cout << "[Stats] EvalMult=" << stats.eval_mult_count << " EvalRotate=" << stats.eval_rotate_count
              << " Relin=" << stats.relinearize_count << std::endl;
    if (FLAGS_fhe_cmp_stats) printComparatorStats(stats, "Polynomial");

    ASSERT_NE(nullptr, output);
    if (FLAGS_validation) {
        auto flags = decryptIndicator(output, row_count);
        ASSERT_EQ(flags.size(), expected_flags.size());
        size_t count_poly = std::count_if(flags.begin(), flags.end(), [](int64_t v) { return v != 0; });
        size_t count_expected = std::count_if(expected_flags.begin(), expected_flags.end(), [](int64_t v) { return v != 0; });
        std::cout << "[Indicator] expected=" << count_expected << ", got=" << count_poly << std::endl;
        for (size_t i = 0; i < expected_flags.size(); ++i)
            EXPECT_EQ(expected_flags[i], flags[i]) << "Mismatch at row " << i;
    }
}

// TEST_F(FheFilterTest, Benchmark_EngorgioStyle) {
//     using namespace std::chrono;
//     std::shared_ptr<FheColumnTable> base_table;
//     int64_t threshold;
//     size_t row_count;
//     std::vector<int64_t> expected_flags;
//     std::vector<Ciphertext<DCRTPoly>> threshold_digits;
//
//     prepareData(base_table, threshold, row_count, expected_flags, threshold_digits);
//
//     std::cout << ">>> Engorgio Style (base4)..." << std::endl;
//     resetComparisonStats();
//     auto eng_pred = makeEngorgioLessEqualPredicate(base_table->getSchema(), "l_shipdate", threshold_digits, kBase4Radix);
//
//     std::string sql = buildSql();
//     SortDefinition collation = DataUtilities::getDefaultSortDefinition(2);
//     std::vector<int32_t> group_by_ordinals = {0, 1};
//     FheSqlInput* input_op = new FheSqlInput(db_name_, sql, collation, 0, 0, true, group_by_ordinals);
//     input_op->setOperatorId(0);
//
//     auto start = high_resolution_clock::now();
//     FheFilter eng_filter(input_op, {eng_pred});
//     eng_filter.setOperatorId(1);
//     auto output = std::dynamic_pointer_cast<FheColumnTable>(eng_filter.runSelf());
//     auto end = high_resolution_clock::now();
//
//     auto duration_ms = duration_cast<milliseconds>(end - start).count();
//     std::cout << "[FheFilterTest] Engorgio: Filter time " << duration_ms << " ms" << std::endl;
//     auto stats = getEngorgioComparisonStats();
//     std::cout << "[Stats] EvalMult=" << stats.eval_mult_count << " EvalRotate=" << stats.eval_rotate_count
//               << " Relin=" << stats.relinearize_count << std::endl;
//     if (FLAGS_fhe_cmp_stats) printComparatorStats(stats, "Engorgio");
//
//     ASSERT_NE(nullptr, output);
//     if (FLAGS_validation) {
//         auto flags = decryptIndicator(output, row_count);
//         ASSERT_EQ(flags.size(), expected_flags.size());
//         size_t count_eng = std::count_if(flags.begin(), flags.end(), [](int64_t v) { return v != 0; });
//         size_t count_expected = std::count_if(expected_flags.begin(), expected_flags.end(), [](int64_t v) { return v != 0; });
//         std::cout << "[Indicator] expected=" << count_expected << ", got=" << count_eng << std::endl;
//         for (size_t i = 0; i < expected_flags.size(); ++i)
//             EXPECT_EQ(expected_flags[i], flags[i]) << "Mismatch at row " << i;
//     }
// }

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    // fhe_filter_test runs single-server only (no B/C), enable by default
    gflags::SetCommandLineOptionWithMode("fhe_single_party", "true", gflags::SET_FLAG_IF_DEFAULT);
    vaultdb::setComparatorStatsEnabled(FLAGS_fhe_cmp_stats);
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::GTEST_FLAG(filter) = FLAGS_filter;
    return RUN_ALL_TESTS();
}
