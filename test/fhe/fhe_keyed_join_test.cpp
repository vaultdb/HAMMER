#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <util/type_utilities.h>
#include <stdexcept>
#include <operators/columnar/fhe_sql_input.h>
#include <operators/columnar/fhe_keyed_join.h>
#include <query_table/columnar/fhe_column_table.h>
#include <expression/simd/simd_generic_expression.h>
#include <expression/simd/simd_comparator_expression_node.h>
#include <util/data_utilities.h>
#include "openfhe.h"
#include <test/fhe/fhe_base_test.h>
#include <util/crypto_manager/fhe_manager.h>
#include <chrono>

// Flags in util/google_test_flags.cpp, DECLAREd in util/google_test_flags.h
using namespace lbcrypto;
using namespace vaultdb;

class FheKeyedJoinTest : public FheBaseTest {

protected:
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    QuantizationParams default_q_params;

    void SetUp() override {
        FheBaseTest::SetUp();

        FheManager& fhe_manager = FheManager::getInstance();

        cc = fhe_manager.getRealCryptoContext();
        pk = fhe_manager.getRealPublicKey();
        sk = fhe_manager.getRealSecretKey();

        ASSERT_NE(nullptr, cc) << "CKKS CryptoContext is null. FheManager not initialized for REAL numbers?";
        ASSERT_NE(nullptr, pk) << "CKKS PublicKey is null.";
        ASSERT_NE(nullptr, sk) << "CKKS SecretKey is null.";

        default_q_params = fhe_manager.getDefaultQuantizationParams();
    }

    void printPlainTable(const vaultdb::PlainColumnTable* table, const std::string& label = "") {
        using namespace vaultdb;

        if (!table) {
            std::cout << "[PrintTable] " << label << " is null." << std::endl;
            return;
        }

        const auto& schema = table->getSchema();
        const auto column_names = table->getColumnNames();
        const size_t row_count = table->getRowCount();

        std::cout << "[PrintTable] " << label << " with " << row_count << " rows:" << std::endl;

        // Print header
        std::cout << "RowIdx\t";
        for (const auto& name : column_names) {
            std::cout << name << "\t";
        }
        std::cout << "\n";

        for (size_t r = 0; r < row_count; ++r) {
            std::cout << r << "\t";
            for (size_t col_idx = 0; col_idx < column_names.size(); ++col_idx) {
                const std::string& col_name = column_names[col_idx];
                auto column = std::dynamic_pointer_cast<PlainColumn>(table->getColumn(col_name));
                if (!column) {
                    std::cout << "[null]\t";
                    continue;
                }

                // Locate the field in the right chunk
                PlainField field;
                size_t remaining = r;
                bool found = false;

                for (const auto& chunk : column->getPlainChunks()) {
                    if (chunk->size() > remaining) {
                        field = chunk->getValue(remaining);
                        found = true;
                        break;
                    } else {
                        remaining -= chunk->size();
                    }
                }

                if (!found) {
                    std::cout << "[err]\t";
                    continue;
                }

                const auto& field_desc = schema.getField(col_idx);
                switch (field_desc.getType()) {
                    case FieldType::INT:
                        std::cout << field.getValue<int32_t>() << "\t";
                        break;
                    case FieldType::LONG:
                        std::cout << field.getValue<int64_t>() << "\t";
                        break;
                    case FieldType::FLOAT:
                        std::cout << field.getValue<float>() << "\t";
                        break;
                    case FieldType::BOOL:
                        std::cout << (field.getValue<bool>() ? "true" : "false") << "\t";
                        break;
                    case FieldType::STRING:
                        std::cout << field.getValue<std::string>() << "\t";
                        break;
                    default:
                        std::cout << "[unsupported]\t";
                }
            }
            std::cout << "\n";
        }
    }
};

// Testing for joining lineitem (FK) with orders (PK) on l_orderkey = o_orderkey
TEST_F(FheKeyedJoinTest, test_fhe_keyed_nlj_optimized) {
    using namespace std::chrono;
    using namespace lbcrypto;

    std::string fk_sql = "SELECT l_orderkey, l_linenumber, FALSE AS dummy_tag FROM lineitem WHERE l_orderkey <= " + std::to_string(FLAGS_cutoff) + " ORDER BY l_orderkey";
    std::string pk_sql = "SELECT o_orderkey, o_orderyear, FALSE AS dummy_tag FROM orders WHERE o_orderkey <= " + std::to_string(FLAGS_cutoff) + " ORDER BY o_orderkey";
    std::string expected_sql = "SELECT l.l_orderkey, l.l_linenumber, o.o_orderyear, (l.dummy_tag OR o.dummy_tag) AS dummy_tag "
                               "FROM (" + fk_sql + ") l "
                                                   "JOIN (" + pk_sql + ") o ON l.l_orderkey = o.o_orderkey "
                                                                       "ORDER BY l.l_orderkey, l.l_linenumber";

    SortDefinition collation = DataUtilities::getDefaultSortDefinition(2);
    std::cout << "[Query] FK: " << fk_sql << std::endl;
    std::cout << "[Query] PK: " << pk_sql << std::endl;

    auto t1 = high_resolution_clock::now();
    FheSqlInput fk_input(db_name_, fk_sql, collation);
    std::shared_ptr<ColumnTableBase<void>> fk_base_output = fk_input.runSelf();
    auto t2 = high_resolution_clock::now();
    std::cout << "[Timing] FK Table Scan: " << duration_cast<milliseconds>(t2 - t1).count() << " ms" << std::endl;

    ASSERT_NE(nullptr, fk_base_output);
    std::shared_ptr<FheColumnTable> fk_table = std::dynamic_pointer_cast<FheColumnTable>(fk_base_output);
    ASSERT_NE(nullptr, fk_table);
    ASSERT_GT(fk_table->getRowCount(), 0);

    auto t3 = high_resolution_clock::now();
    FheSqlInput pk_input(db_name_, pk_sql, collation);
    std::shared_ptr<ColumnTableBase<void>> pk_base_output = pk_input.runSelf();
    auto t4 = high_resolution_clock::now();
    std::cout << "[Timing] PK Table Scan: " << duration_cast<milliseconds>(t4 - t3).count() << " ms" << std::endl;

    ASSERT_NE(nullptr, pk_base_output);
    std::shared_ptr<FheColumnTable> pk_table = std::dynamic_pointer_cast<FheColumnTable>(pk_base_output);
    ASSERT_NE(nullptr, pk_table);
    ASSERT_GT(pk_table->getRowCount(), 0);

    const auto& fk_schema = fk_table->getSchema();
    const auto& pk_schema = pk_table->getSchema();

    // ==== Build SIMD Join Condition: l_orderkey == o_orderkey ====
    // Create references to the join key columns
    auto fk_key_ref = std::make_shared<SIMDPackedInputReference<FheColumnChunk>>(0, fk_schema); // l_orderkey is column 0
    auto pk_key_ref = std::make_shared<SIMDPackedInputReference<FheColumnChunk>>(0, pk_schema); // o_orderkey is column 0

    // Create equality comparison node
    auto eq_node = std::make_shared<SIMDEqualNode<FheColumnChunk>>(fk_key_ref, pk_key_ref);

    SIMDFheGenericExpression join_condition(eq_node, FieldType::BOOL);

    // ==== Run Join ====
    auto t5 = high_resolution_clock::now();
    FheKeyedJoin join_op(fk_table, pk_table, join_condition, "l_orderkey", "o_orderkey", 0);
    std::shared_ptr<FheColumnTable> join_result =
            std::dynamic_pointer_cast<FheColumnTable>(join_op.runSelf());
    auto t6 = high_resolution_clock::now();
    std::cout << "[Timing] FHE Keyed Join: " << duration_cast<milliseconds>(t6 - t5).count() << " ms" << std::endl;

    ASSERT_NE(nullptr, join_result);

    // Validation
    if (FLAGS_validation) {
        std::unique_ptr<PlainColumnTable> expected = DataUtilities::getQueryColumnTable(FLAGS_unioned_db, expected_sql);
        PlainColumnTable* revealed = join_result.get()->reveal();

        printPlainTable(revealed, "Decrypted Join Result");

        ASSERT_NE(nullptr, revealed);
        ASSERT_EQ(*expected, *revealed);

        delete revealed;
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}