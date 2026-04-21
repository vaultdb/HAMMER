#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <vector>
#include <ctime>

#include <operators/columnar/fhe_sql_input.h>
#include <query_table/columnar/fhe_column_table.h>
#include <query_table/columnar/plain_column_chunk.h>
#include <util/data_utilities.h>
#include <util/type_utilities.h>

#include <test/fhe/fhe_base_test.h>
#include <util/crypto_manager/fhe_manager.h>

// Flags in util/google_test_flags.cpp, DECLAREd in util/google_test_flags.h
using namespace lbcrypto;
using namespace vaultdb;

class FheTableScanTest : public FheBaseTest {
protected:
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;

    void SetUp() override {
        FheBaseTest::SetUp();

        FheManager& fhe_manager = FheManager::getInstance();
        cc = fhe_manager.getIntegerCryptoContext();
        pk = fhe_manager.getIntegerPublicKey();
        sk = fhe_manager.getIntegerSecretKey();

        ASSERT_NE(nullptr, cc) << "BFV CryptoContext is null.";
        ASSERT_NE(nullptr, pk) << "BFV PublicKey is null.";
        ASSERT_NE(nullptr, sk) << "BFV SecretKey is null.";
    }
};

namespace {
void printTableHead(const PlainColumnTable& table, const std::string& label = "table_head", size_t rows = 5) {
    std::cout << "[" << label << "] first " << rows << " rows" << std::endl;
    const auto& schema = table.getSchema();
    auto column_names = table.getColumnNames();

    for (const auto& name : column_names) {
        std::cout << name << "\t";
    }
    std::cout << "\n";

    const size_t limit = std::min(rows, table.getRowCount());
    for (size_t r = 0; r < limit; ++r) {
        for (const auto& name : column_names) {
            auto column = table.getPlainColumn(name);
            if (!column) {
                std::cout << "[null]\t";
                continue;
            }
            size_t remaining = r;
            PlainField field;
            bool found = false;
            for (const auto& chunk : column->getPlainChunks()) {
                if (!chunk) continue;
                if (remaining < chunk->size()) {
                    field = chunk->getValue(remaining);
                    found = true;
                    break;
                }
                remaining -= chunk->size();
            }
            if (!found) {
                std::cout << "[err]\t";
                continue;
            }

            switch (field.getType()) {
                case FieldType::BOOL:
                    std::cout << (field.getValue<bool>() ? "true" : "false");
                    break;
                case FieldType::INT:
                    std::cout << field.getValue<int32_t>();
                    break;
                case FieldType::LONG:
                case FieldType::DATE:
                    std::cout << field.getValue<int64_t>();
                    break;
                case FieldType::FLOAT:
                    std::cout << field.getValue<float>();
                    break;
                default:
                    std::cout << "[?]";
                    break;
            }
            std::cout << "\t";
        }
        std::cout << "\n";
    }
}
}

TEST_F(FheTableScanTest, encrypts_with_group_by_and_checks_ciphertext_counts) {
    using Clock = std::chrono::high_resolution_clock;
    using ms = std::chrono::milliseconds;

    // Use same columns as aggregate test for consistency
    const std::string sql = FLAGS_cutoff == -1
                            ? "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem ORDER BY (1), (2)"
                            : "SELECT l_returnflag, l_linestatus, l_orderkey, l_shipdate FROM lineitem WHERE l_orderkey <= " + std::to_string(FLAGS_cutoff) + " ORDER BY (1), (2)";

    SortDefinition collation = DataUtilities::getDefaultSortDefinition(2);
    std::cout << "[Query] " << sql << std::endl;

    // Group by l_returnflag (ordinal 0) and l_linestatus (ordinal 1)
    std::vector<int32_t> group_by_ordinals = {0, 1};

    auto t1 = Clock::now();
    // Pass group_by_ordinals to create bin metadata with continuous packing
    FheSqlInput sql_input(db_name_, sql, collation, 0, 0, true, group_by_ordinals);
    std::shared_ptr<ColumnTableBase<void>> encrypted_output = sql_input.runSelf();
    auto t2 = Clock::now();
    std::cout << "[Timing] Encrypted Table Scan (with Bin Metadata): "
              << std::chrono::duration_cast<ms>(t2 - t1).count() << " ms" << std::endl;

    auto encrypted_table = std::dynamic_pointer_cast<FheColumnTable>(encrypted_output);
    ASSERT_NE(nullptr, encrypted_table);
    ASSERT_GT(encrypted_table->getRowCount(), 0);

    // Check ciphertext count for each column after scan
    std::cout << "[Scan Result] Ciphertext chunk counts per column:" << std::endl;
    auto column_names = encrypted_table->getColumnNames();
    for (const auto& col_name : column_names) {
        auto fhe_col = encrypted_table->getFheColumn(col_name);
        if (fhe_col) {
            size_t chunk_count = fhe_col->getFheChunks().size();
            size_t row_count_col = fhe_col->getRowCount();
            std::cout << "  Column '" << col_name << "': " << chunk_count 
                      << " ciphertext chunks, " << row_count_col << " rows" << std::endl;
        }
    }

    // Check bin metadata if exists
    if (encrypted_table->hasBinMetadata()) {
        const auto& bin_metadata = encrypted_table->getBinMetadata();
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

    auto expected_plain = std::make_unique<PlainColumnTable>(*encrypted_table->getPlainSnapshot());
    ASSERT_GT(expected_plain->getRowCount(), 0);
    EXPECT_EQ(encrypted_table->getRowCount(), expected_plain->getRowCount());

    if (FLAGS_validation) {
        const auto reveal_start = Clock::now();
        std::unique_ptr<PlainColumnTable> revealed(encrypted_table->toPlainTable());
        const auto reveal_end = Clock::now();

        ASSERT_NE(nullptr, revealed);

        std::cout << "[Timing] Decrypt FHE columns -> Plain table: "
                  << std::chrono::duration_cast<ms>(reveal_end - reveal_start).count() << " ms" << std::endl;

        printTableHead(*expected_plain, "expected_plain", 5);
        printTableHead(*revealed, "revealed_plain", 5);

        ASSERT_EQ(*expected_plain, *revealed) << "Round-trip mismatch after encryption/decryption.";
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

