#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <util/type_utilities.h>
#include <stdexcept>
#include <operators/columnar/fhe_sql_input.h>
#include <operators/columnar/fhe_filter.h>
#include <operators/columnar/fhe_aggregate.h>
#include <query_table/columnar/fhe_column_table.h>
#include <util/data_utilities.h>
#include "openfhe.h"
#include <test/fhe/fhe_base_test.h>
#include <util/crypto_manager/fhe_manager.h>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <iomanip>
#include <map>
#include <string>
#include <operators/support/aggregate_id.h>
// Flags in fhe_base_test.h
using namespace lbcrypto;
using namespace vaultdb;

namespace {
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
            t.tm_hour = 0;
            t.tm_min = 0;
            t.tm_sec = 0;
            t.tm_isdst = -1;
            return t;
        };

        const int64_t seconds_per_day = 24 * 3600;

        const auto compute_days = [&](const std::string& str) {
            std::tm tm_copy = parse_date(str);
            return static_cast<int64_t>(mktime(&tm_copy) / seconds_per_day);
        };

        static const int64_t base_days = compute_days(base_date);
        const int64_t current_days = compute_days(date_str);
        return current_days - base_days;
    }

    // Helper functions from fhe_filter_test.cpp
    std::vector<int64_t> encodeRadixDigits(int64_t value, size_t radix_base, size_t num_digits) {
        std::vector<int64_t> digits(num_digits, 0);
        int64_t remaining = value;
        for (size_t i = 0; i < num_digits && remaining > 0; ++i) {
            digits[i] = remaining % radix_base;
            remaining /= radix_base;
        }
        return digits;
    }

    std::vector<Ciphertext<DCRTPoly>> encryptRadixDigits(int64_t threshold,
                                                         size_t radix_base,
                                                         size_t num_digits) {
        FheManager& manager = FheManager::getInstance();
        auto cc = manager.getComparisonCryptoContext();
        auto pk = manager.getComparisonPublicKey();
        if (!cc || !pk) {
            throw std::runtime_error("encryptRadixDigits: comparison crypto context unavailable");
        }

        auto digits = encodeRadixDigits(threshold, radix_base, num_digits);
        size_t pack_slots = manager.getBFVComparisonBatchSize();
        std::vector<Ciphertext<DCRTPoly>> digit_ciphers(num_digits);

        for (size_t d = 0; d < num_digits; ++d) {
            std::vector<int64_t> digit_vec(pack_slots, digits[d]);
            Plaintext pt = cc->MakePackedPlaintext(digit_vec);
            digit_ciphers[d] = cc->Encrypt(pk, pt);
        }
        return digit_ciphers;
    }

    std::vector<int64_t> decryptIndicator(const std::shared_ptr<FheColumnTable>& table,
                                         size_t row_count) {
        auto indicator_col = table->getDummyTagColumn();
        if (!indicator_col) {
            throw std::runtime_error("Indicator column is not set");
        }

        FheManager& manager = FheManager::getInstance();
        auto cc = manager.getComparisonCryptoContext();
        auto sk = manager.getComparisonSecretKey();
        if (!cc || !sk) {
            throw std::runtime_error("Comparison crypto context unavailable");
        }

        std::vector<int64_t> indicator_values;
        indicator_values.reserve(row_count);

        for (const auto& chunk : indicator_col->getFheChunks()) {
            Plaintext pt;
            cc->Decrypt(sk, chunk->getCiphertext(), &pt);
            auto pt_vec = pt->GetPackedValue();
            size_t effective_count = chunk->packed_count;
            for (size_t i = 0; i < effective_count && indicator_values.size() < row_count; ++i) {
                indicator_values.push_back(static_cast<int64_t>(pt_vec[i]));
            }
        }

        indicator_values.resize(row_count);
        return indicator_values;
    }

    // Helper to get field value from plain table (numeric types)
    int64_t getFieldValueHelper(PlainColumnTable* table, int32_t ordinal, size_t row);
    
    // Helper to get string field value from plain table
    std::string getStringFieldValueHelper(PlainColumnTable* table, int32_t ordinal, size_t row);
}

    // Group size information structure (will be provided from JSON later)
    struct GroupSizeInfo {
        std::string group_key;  // e.g., "A|F"
        size_t row_count;       // e.g., 14876
    };

class FheAggregateTest : public FheBaseTest {
protected:
    void SetUp() override {
        FheBaseTest::SetUp();
    }
    
    // Group size information for tpch_unioned_1500 (GROUP BY l_returnflag, l_linestatus)
    // This will be provided from JSON later, but for now hardcoded for testing
    std::vector<GroupSizeInfo> getGroupSizes() {
        return {
            {"A|F", 14876},
            {"N|F", 348},
            {"N|O", 30049},
            {"R|F", 14902}
        };
    }
    
    // Data preparation function (similar to fhe_filter_test)
    void prepareData(std::shared_ptr<FheColumnTable>& base_table, 
                     int64_t& threshold_relative, 
                     size_t& row_count,
                     std::vector<Ciphertext<DCRTPoly>>& threshold_digits) {
        
        const std::string sql = FLAGS_cutoff == -1
            ? "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem ORDER BY (1), (2)"
            : "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem WHERE l_orderkey <= " + std::to_string(FLAGS_cutoff) + " ORDER BY (1), (2)";

        SortDefinition collation = DataUtilities::getDefaultSortDefinition(2);
        std::cout << "[Query] " << sql << std::endl;

        // Group by l_returnflag (ordinal 0) and l_linestatus (ordinal 1)
        std::vector<int32_t> group_by_ordinals = {0, 1};
        
        auto t1 = std::chrono::high_resolution_clock::now();
        // Pass group_by_ordinals to create bin metadata with continuous packing
        FheSqlInput input(db_name_, sql, collation, 0, 0, true, group_by_ordinals);
        auto base_output_table = input.runSelf();
        auto t2 = std::chrono::high_resolution_clock::now();
        std::cout << "[Timing] Encrypted Table Scan (with Bin Metadata): " << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << " ms" << std::endl;

        ASSERT_NE(nullptr, base_output_table);
        base_table = std::dynamic_pointer_cast<FheColumnTable>(base_output_table);
        ASSERT_NE(nullptr, base_table);
        ASSERT_GT(base_table->getRowCount(), 0);
        
        // Check ciphertext count for each column after scan
        std::cout << "[Scan Result] Ciphertext chunk counts per column:" << std::endl;
        auto column_names = base_table->getColumnNames();
        for (const auto& col_name : column_names) {
            auto fhe_col = base_table->getFheColumn(col_name);
            if (fhe_col) {
                size_t chunk_count = fhe_col->getFheChunks().size();
                size_t row_count_col = fhe_col->getRowCount();
                std::cout << "  Column '" << col_name << "': " << chunk_count 
                          << " ciphertext chunks, " << row_count_col << " rows" << std::endl;
            }
        }
        
        // Check bin metadata if exists
        if (base_table->hasBinMetadata()) {
            const auto& bin_metadata = base_table->getBinMetadata();
            std::cout << "[Bin Metadata] Number of groups: " << bin_metadata.size() << std::endl;
            for (size_t i = 0; i < std::min<size_t>(10, bin_metadata.size()); ++i) {
                const auto& group_meta = bin_metadata[i];
                std::cout << "  Group " << i << ": rows " << group_meta.original_start_row 
                          << "-" << group_meta.original_end_row;
                for (const auto& [col_name, bin_info] : group_meta.column_bin_info) {
                    std::cout << ", " << col_name << " (chunks " << bin_info.start_chunk_idx 
                              << "-" << bin_info.end_chunk_idx 
                              << ", packed_count=" << bin_info.total_packed_count << ")";
                }
                std::cout << std::endl;
            }
        }
        
        auto plain_snapshot = base_table->getPlainSnapshot();
        ASSERT_NE(nullptr, plain_snapshot);
        row_count = plain_snapshot->getRowCount();
        threshold_relative = relativeDaysFromDateString("1995-12-31");
        
        // encrypt threshold
        threshold_digits = encryptRadixDigits(threshold_relative, 8, 4);
    }
};

// Test 1: Filter -> Aggregate (COUNT)
TEST_F(FheAggregateTest, filter_then_count_test) {
    using namespace std::chrono;
    
    std::shared_ptr<FheColumnTable> base_table;
    int64_t threshold;
    size_t row_count;
    std::vector<Ciphertext<DCRTPoly>> threshold_digits;

    // Prepare data (with group-by scan, same as fhe_filter_test)
    prepareData(base_table, threshold, row_count, threshold_digits);

    std::cout << ">>> Running Filter -> COUNT Aggregate Test..." << std::endl;
    
    // Step 1: Create filter operator (will be executed by aggregate)
    resetComparisonStats();
    auto poly_pred = makePolynomialLessEqualPredicate(base_table->getSchema(), "l_shipdate", threshold_digits, 8);
    
    // Create FheSqlInput operator to use as child for FheFilter
    const std::string sql = FLAGS_cutoff == -1
            ? "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem ORDER BY (1), (2)"
            : "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem WHERE l_orderkey <= " + std::to_string(FLAGS_cutoff) + " ORDER BY (1), (2)";
    SortDefinition collation = DataUtilities::getDefaultSortDefinition(2);
    std::vector<int32_t> group_by_ordinals = {0, 1};
    FheSqlInput* input_op = new FheSqlInput(db_name_, sql, collation, 0, 0, true, group_by_ordinals);
    input_op->setOperatorId(0);
    
    // Create filter operator (don't run it yet - aggregate will call it)
    FheFilter filter(input_op, {poly_pred});
    filter.setOperatorId(1);

    // Step 2: Aggregate (COUNT) on filtered result
    // Group-by ordinals are automatically taken from bin metadata (created during scan)
    // FheAggregate will internally call filter.runSelf()
    std::vector<ScalarAggregateDefinition> aggregates;
    aggregates.emplace_back(-1, AggregateId::COUNT, "cnt");  // COUNT(*)

    auto agg_start = high_resolution_clock::now();
    FheAggregate agg(&filter, aggregates);
    agg.setOperatorId(2);
    auto agg_output = std::dynamic_pointer_cast<FheColumnTable>(agg.runSelf());
    auto agg_end = high_resolution_clock::now();
    std::cout << "[Timing] FHE Aggregate (COUNT): " << duration_cast<milliseconds>(agg_end - agg_start).count() << " ms" << std::endl;
    
    // Print filter stats after aggregate execution (filter was executed by aggregate)
    auto poly_stats = getPolynomialComparisonStats();
    std::cout << "[Filter Stats] EvalMult: " << poly_stats.eval_mult_count
              << ", EvalRotate: " << poly_stats.eval_rotate_count
              << ", Ciphertext: " << poly_stats.ciphertext_count << std::endl;

    ASSERT_NE(nullptr, agg_output);

    if (FLAGS_validation) {
        std::cout << ">>> Decrypting result table..." << std::endl;
        auto revealed = agg_output->reveal();
        ASSERT_NE(nullptr, revealed);

        size_t row_count = revealed->getRowCount();
        std::cout << "[Output] Group count: " << row_count << std::endl;
        
        // Check column names (for debugging)
        auto cols = revealed->getColumnNames();
        std::cout << "[Debug] Output Schema: ";
        for (const auto& c : cols) std::cout << c << ", ";
        std::cout << std::endl;

        std::cout << ">>> Dumping Raw Counts (Index 2)..." << std::endl;
        
        // Expected values (checking only values regardless of order)
        std::vector<int64_t> expected_values = {14876, 348, 4852, 14902}; // Expected answer for Test 1
        
        for (size_t i = 0; i < row_count; ++i) {
            try {
                // Skip columns 0, 1 (String Key) and get column 2 (cnt) only.
                // Since cnt was added last in the aggregate definition, index 2 is correct.
                int64_t cnt = getFieldValueHelper(revealed, 2, i);
                
                std::cout << "  Row " << i << " | Count: " << cnt << std::endl;
            } catch (const std::exception& e) {
                std::cout << "  Row " << i << " | Error reading count: " << e.what() << std::endl;
            }
        }
    }
}

// Test 2: Filter -> Aggregate (SUM)
TEST_F(FheAggregateTest, filter_then_sum_test) {
    using namespace std::chrono;
    
    std::shared_ptr<FheColumnTable> base_table;
    int64_t threshold;
    size_t row_count;
    std::vector<Ciphertext<DCRTPoly>> threshold_digits;

    // Prepare data
    prepareData(base_table, threshold, row_count, threshold_digits);

    std::cout << ">>> Running Filter -> SUM Aggregate Test..." << std::endl;
    
    // Step 1: Filter (using polynomial style) - same as fhe_filter_test
    resetComparisonStats();
    auto poly_pred = makePolynomialLessEqualPredicate(base_table->getSchema(), "l_shipdate", threshold_digits, 8);
    
    // Create FheSqlInput operator to use as child for FheFilter
    const std::string sql = FLAGS_cutoff == -1
            ? "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem ORDER BY (1), (2)"
            : "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem WHERE l_orderkey <= " + std::to_string(FLAGS_cutoff) + " ORDER BY (1), (2)";
    SortDefinition collation = DataUtilities::getDefaultSortDefinition(2);
    std::vector<int32_t> group_by_ordinals = {0, 1};
    FheSqlInput* input_op = new FheSqlInput(db_name_, sql, collation, 0, 0, true, group_by_ordinals);
    input_op->setOperatorId(0);
    
    auto filter_start = high_resolution_clock::now();
    FheFilter filter(input_op, {poly_pred});
    filter.setOperatorId(1);
    auto filtered_table = std::dynamic_pointer_cast<FheColumnTable>(filter.runSelf());
    auto filter_end = high_resolution_clock::now();
    std::cout << "[Timing] FHE Filter: " << duration_cast<milliseconds>(filter_end - filter_start).count() << " ms" << std::endl;
    auto poly_stats = getPolynomialComparisonStats();
    std::cout << "[Filter Stats] EvalMult: " << poly_stats.eval_mult_count
              << ", EvalRotate: " << poly_stats.eval_rotate_count
              << ", Ciphertext: " << poly_stats.ciphertext_count << std::endl;

    ASSERT_NE(nullptr, filtered_table);

    // Step 2: Aggregate (SUM) on l_orderkey (ordinal 2, since schema is l_returnflag, l_linestatus, l_orderkey, l_shipdate)
    // Group-by ordinals are automatically taken from bin metadata (created during scan)
    std::vector<ScalarAggregateDefinition> aggregates;
    aggregates.emplace_back(2, AggregateId::SUM, "sum_orderkey");  // SUM(l_orderkey)

    auto agg_start = high_resolution_clock::now();
    FheAggregate agg(&filter, aggregates);
    agg.setOperatorId(2);
    auto agg_output = std::dynamic_pointer_cast<FheColumnTable>(agg.runSelf());
    auto agg_end = high_resolution_clock::now();
    std::cout << "[Timing] FHE Aggregate (SUM): " << duration_cast<milliseconds>(agg_end - agg_start).count() << " ms" << std::endl;

    ASSERT_NE(nullptr, agg_output);

    if (FLAGS_validation) {
        auto revealed = agg_output->reveal();
        ASSERT_NE(nullptr, revealed);

        std::cout << "[Output] Group count: " << revealed->getRowCount() << std::endl;
        std::cout << "[Output] Sample rows:" << std::endl;
        
        for (size_t i = 0; i < revealed->getRowCount(); ++i) {
            std::string ret_flag = getStringFieldValueHelper(revealed, 0, i);
            std::string line_status = getStringFieldValueHelper(revealed, 1, i);
            int64_t sum_orderkey = getFieldValueHelper(revealed, 2, i);
            std::cout << "  Row " << i << ": returnflag=" << ret_flag
                      << ", linestatus=" << line_status
                      << ", sum_orderkey=" << sum_orderkey << std::endl;
        }
    }
}

namespace {
    // Helper to get field value from plain table
    int64_t getFieldValueHelper(PlainColumnTable* table, int32_t ordinal, size_t row) {
        if (!table) {
            throw std::runtime_error("FheAggregateTest: table is null");
        }
        auto field_desc = table->getSchema().getField(ordinal);
        auto column = table->getPlainColumn(field_desc.getName());
        if (!column) {
            throw std::runtime_error("FheAggregateTest: column not found: " + field_desc.getName());
        }

        size_t chunk_idx = 0, offset = row;
        for (const auto& chunk : column->getPlainChunks()) {
            if (!chunk) continue;
            size_t chunk_size = chunk->getValues().size();
            if (offset < chunk_size) break;
            offset -= chunk_size;
            chunk_idx++;
        }

        const auto& chunks = column->getPlainChunks();
        if (chunk_idx >= chunks.size() || !chunks[chunk_idx]) {
            throw std::runtime_error("FheAggregateTest: row index out of range");
        }

        const auto& field = chunks[chunk_idx]->getValues()[offset];
        switch (field.getType()) {
            case FieldType::INT: return static_cast<int64_t>(field.getValue<int32_t>());
            case FieldType::LONG:
            case FieldType::DATE: return field.getValue<int64_t>();
            case FieldType::BOOL: return field.getValue<bool>() ? 1 : 0;
            default: throw std::runtime_error("FheAggregateTest: unsupported field type");
        }
    }
    
    // Helper to get string field value from plain table
    std::string getStringFieldValueHelper(PlainColumnTable* table, int32_t ordinal, size_t row) {
        if (!table) {
            throw std::runtime_error("FheAggregateTest: table is null");
        }
        auto field_desc = table->getSchema().getField(ordinal);
        auto column = table->getPlainColumn(field_desc.getName());
        if (!column) {
            throw std::runtime_error("FheAggregateTest: column not found: " + field_desc.getName());
        }

        size_t chunk_idx = 0, offset = row;
        for (const auto& chunk : column->getPlainChunks()) {
            if (!chunk) continue;
            size_t chunk_size = chunk->getValues().size();
            if (offset < chunk_size) break;
            offset -= chunk_size;
            chunk_idx++;
        }

        const auto& chunks = column->getPlainChunks();
        if (chunk_idx >= chunks.size() || !chunks[chunk_idx]) {
            throw std::runtime_error("FheAggregateTest: row index out of range");
        }

        const auto& field = chunks[chunk_idx]->getValues()[offset];
        if (field.getType() == FieldType::STRING) {
            return field.getValue<std::string>();
        } else {
            throw std::runtime_error("FheAggregateTest: getStringFieldValueHelper called on non-string field type: " + 
                                    std::to_string(static_cast<int>(field.getType())));
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    return RUN_ALL_TESTS();
}






