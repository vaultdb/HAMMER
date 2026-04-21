#ifndef _FHE_BASE_TEST_H
#define _FHE_BASE_TEST_H

#include <cstdint>
#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <util/logger.h>
#include <util/crypto_manager/fhe_manager.h>
#include <util/data_utilities.h>
#include <util/system_configuration.h>
#include <query_table/columnar/column_table_base.h>
#include <query_table/columnar/column_base.h>
#include <query_table/columnar/plain_column_chunk.h>
#include <util/fhe/fhe_network.h>
#include <util/fhe/fhe_predicate_types.h>
#include <memory>
#include <map>
#include "openfhe.h"

#include <vector>
#include <util/google_test_flags.h>

// When fhe_single_party=true, SetUp skips 3-party network (for fhe_filter_test etc)

using namespace lbcrypto;
using namespace Logging;

namespace vaultdb {

    // Forward declaration
    class FheColumnTable;

    /// Result-type header sent by Party B before result payload. Party A reads this to branch.
    constexpr int32_t kResultModeFheColumnar = 0;    ///< FHE ColumnTable (encrypted columns)
    constexpr int32_t kResultModeMpcRowShares = 1;  ///< MPC secret-shared rows (B + C shares)

    struct PredicateDef {
        std::string table_name;      // e.g. "lineitem" - required for DictionaryManager
        std::string column_name;     // wire key for encrypted predicate map (e.g. "l_shipdate" or "o_orderdate_less_than")
        std::string predicate_type;  // "less_equal", "greater_than", etc.
        std::string threshold_value;
    };

    class FheBaseTest : public ::testing::Test {
    protected:
        static const std::string empty_db_;
        static const CryptoMode crypto_mode_;

        static std::string db_name_;
        static const StorageModel storage_model_;
        static FheManager *manager_;
        
        // 2-party network communication (Party A <-> Party B)
        std::unique_ptr<FheNetworkIO> network_io_;
        // Party A <-> Party C connection (needed for direct share transfer)
        std::unique_ptr<FheNetworkIO> network_io_charlie_;
        
        // MPC network communication (Party B <-> Party C for distributed decryption)
        std::unique_ptr<FheNetworkIO> mpc_network_io_;
        
        // Encrypted predicates: digits + radix strategy (from Party A / Dict)
        EncryptedPredicatesMap encrypted_predicates_map_;
        
        // Party A's CryptoContext and PublicKey (received by Party B during setup)
        // Party B must use these for operations with ciphertexts encrypted by Party A
        CryptoContext<DCRTPoly> cc_from_party_A_;
        PublicKey<DCRTPoly> pk_from_party_A_;
        
        // Secret Key Share (received by Party B and Party C during 3-party setup)
        // Used for distributed decryption
        PrivateKey<DCRTPoly> my_secret_key_share_;

        static const CryptoContext<DCRTPoly>* int_crypto_context_;
        static const KeyPair<DCRTPoly>* int_key_pair_;
        static const CryptoContext<DCRTPoly>* real_crypto_context_;
        static const KeyPair<DCRTPoly>* real_key_pair_;
        static const BinFHEContext* bool_crypto_context_;
        static const LWEPrivateKey* bool_key_pair_;

        static void SetUpTestSuite();
        static void TearDownTestSuite();
        
        void SetUp() override;
        void TearDown() override;

        void disableBitPacking();
        void initializeBitPacking(const std::string & unioned_db);
        
        // 2-party network access
        FheNetworkIO* getNetworkIO() { return network_io_.get(); }
        FheNetworkIO* getCharlieNetworkIO() { return network_io_charlie_.get(); }
        
        // Predicate management
        const EncryptedPredicatesMap& getEncryptedPredicates() const {
            return encrypted_predicates_map_;
        }
        
        // Get Party A's CryptoContext (for Party B to use in operations)
        const CryptoContext<DCRTPoly>& getPartyACryptoContext() const {
            return cc_from_party_A_;
        }
        
        // Get Party A's PublicKey (for Party B to use in operations)
        const PublicKey<DCRTPoly>& getPartyAPublicKey() const {
            return pk_from_party_A_;
        }
        
        // Send predicates from Party A (to be implemented/overridden by derived classes)
        virtual void sendPredicates();

        void sendPredicatesFromVector(const std::vector<PredicateDef>& predicates);

        /// Build PredicateDef from SQL predicate (table.col op value).
        /// wire_key: map key for encrypted predicate (default=column; use "col_predtype" for disambiguation).
        static PredicateDef buildPredicateDefFromSQL(const std::string& table,
            const std::string& column, const std::string& op, const std::string& value,
            const std::string& wire_key = "");
        std::string generateExpectedOutputQuery(const int& test_id, const std::string& db_name);

        // Receive predicates on Party B
        void receivePredicates();
        
        // Send result table from Party B to Party A
        void sendResultTable(std::shared_ptr<FheColumnTable> result_table);
        
        // Receive result table on Party A from Party B
        std::shared_ptr<FheColumnTable> receiveResultTable();
        
        // Distributed Decryption Protocol (Party B and Party C)
        // Converts FHE ciphertext result to MPC shares using Masked Exchange
        // Returns a pair of DCRTPoly shares: (Share_B, Share_C)
        // Note: Each party only holds its own share (the other is empty)
        std::pair<lbcrypto::DCRTPoly, lbcrypto::DCRTPoly> RunDistributedDecryptionProtocol(
            const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c_agg);
        
        static int64_t baseRelativeEpochDays();
        static int64_t relativeDaysFromField(const PlainField& field);
        static void normalizeDateColumn(PlainColumnTable& table, const std::string& column_name);
        static void normalizeDateColumns(PlainColumnTable& table, const std::vector<std::string>& column_names);
        static void normalizeDateColumnsAuto(PlainColumnTable& table);

        std::vector<LWECiphertext> EncryptBits(const std::vector<bool>& bits, const BinFHEContext& cc, const LWEPrivateKey& boolKey);
        std::vector<bool> DecryptBits(const std::vector<LWECiphertext>& encryptedBits, const BinFHEContext& cc, const LWEPrivateKey& boolKey);

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

                    // Special-case handling for dummy_tag column
                    if (col_name == "dummy_tag") {
                        switch (field.getType()) {
                            case FieldType::BOOL:
                                std::cout << (field.getValue<bool>() ? "true" : "false") << "\t";
                                break;
                            case FieldType::INT:
                                std::cout << (field.getValue<int32_t>() ? "true" : "false") << "\t";
                                break;
                            case FieldType::LONG:
                                std::cout << (field.getValue<int64_t>() ? "true" : "false") << "\t";
                                break;
                            case FieldType::FLOAT:
                                std::cout << (field.getValue<float>() > 0.5f ? "true" : "false") << "\t";
                                break;
                            default:
                                std::cout << "? ";
                                break;
                        }
                        continue;
                    }
                    else {
                        switch (field.getType()) {
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
                }
                std::cout << "\n";
            }
        }
    };

} // namespace vaultdb

#endif // _FHE_BASE_TEST_H
