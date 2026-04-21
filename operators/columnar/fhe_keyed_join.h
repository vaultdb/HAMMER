#ifndef _FHE_KEYED_JOIN_H_
#define _FHE_KEYED_JOIN_H_

#include "openfhe.h"
#include <operators/columnar/column_operator.h>
#include <query_table/columnar/fhe_column_table.h>
#include <expression/simd/simd_generic_expression.h>
#include <string>
#include <memory>
#include <vector>
#include <util/crypto_manager/fhe_manager.h>
#include <util/fhe/fhe_comparator.h>

namespace vaultdb {

    class FheKeyedJoin : public ColumnOperator<void> {
    private:
        std::shared_ptr<FheColumnTable> lhs_table_;
        std::shared_ptr<FheColumnTable> rhs_table_;
        SIMDFheGenericExpression join_condition_;
        std::string fk_join_key_name_;
        std::string pk_join_key_name_;
        int foreign_key_input_; // 0 = lhs is FK, 1 = rhs is FK

        // Cached rotated FK keys for each chunk and rotation
        std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> fk_rotated_keys_cache_;
        bool precomputed_cache_provided_ = false;

        // Helper methods
        void precomputeRotatedFKKeys();
        void precomputeFastRotatedFKKeys();
        std::shared_ptr<FheColumnTable> performJoin();
        void addColumnToOutput(std::shared_ptr<FheColumnTable>& output,
                               const std::string& col_name,
                               const std::shared_ptr<FheColumnTable>& source_table);
        void updateDummyTag(std::shared_ptr<FheColumnTable>& output,
                            size_t chunk_idx,
                            const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& mask);

    public:
        FheKeyedJoin(std::shared_ptr<FheColumnTable> lhs,
                std::shared_ptr<FheColumnTable> rhs,
                const SIMDFheGenericExpression& join_condition,
                const std::string& fk_join_key,
                const std::string& pk_join_key,
                int foreign_key_input = 0);

        std::shared_ptr<ColumnTableBase<void>> runSelf() override;

        // Method to inject precomputed cache (for hybrid approach)
        void setPrecomputedCache(const std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>>& cache);

        // Method to accept plaintext cache and do encryption internally (for hybrid approach)
        void setPlaintextCacheAndEncrypt(const std::vector<std::vector<std::vector<PlainField>>>& plaintext_cache);

        Ciphertext<DCRTPoly> rotateByBinaryDecomposition(CryptoContext<DCRTPoly> cc,
                                                         const Ciphertext<DCRTPoly>& ct,
                                                         int rotation_amount,
                                                         uint32_t slot_size);

        OperatorType getType() const override;

        std::string getParameters() const override {
            return "FK=" + fk_join_key_name_ + ", PK=" + pk_join_key_name_ +
                   ", FK_input=" + std::to_string(foreign_key_input_);
        }

        void updateCollation() override {
            // For now, no collation updates needed
        }
    };

} // namespace vaultdb

#endif // _FHE_KEYED_JOIN_H_