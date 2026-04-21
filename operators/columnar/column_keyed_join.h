#ifndef _COLUMN_KEYED_JOIN_H_
#define _COLUMN_KEYED_JOIN_H_

#include "openfhe.h"
#include <operators/columnar/column_operator.h>
#include <query_table/columnar/column_table_base.h>
#include <expression/simd/simd_generic_expression.h>
#include <string>
#include <memory>
#include <vector>

namespace vaultdb {

    class ColumnKeyedJoin : public ColumnOperator<bool> {
    private:
        std::shared_ptr<PlainColumnTable> lhs_table_;
        std::shared_ptr<PlainColumnTable> rhs_table_;
        SIMDPlainGenericExpression join_condition_;
        std::string fk_join_key_name_;
        std::string pk_join_key_name_;
        int foreign_key_input_; // 0 = lhs is FK, 1 = rhs is FK

        // Cached rotated FK keys for each chunk and rotation (plaintext version)
        std::vector<std::vector<std::vector<PlainField>>> fk_rotated_keys_cache_;

        // Static debug flag to control debug output
        static bool debug_enabled_;

        // Debug print helper method
        void debugPrint(const std::string& message);

        // Helper methods
        void precomputeRotatedFKKeys(const size_t chunk_size);
        std::shared_ptr<PlainColumnTable> performJoin(const size_t chunk_size);
        void addColumnToOutput(std::shared_ptr<PlainColumnTable>& output,
                               const std::string& col_name,
                               const std::shared_ptr<PlainColumnTable>& source_table,
                               const size_t chunk_size);

    public:
        ColumnKeyedJoin(std::shared_ptr<PlainColumnTable> lhs,
                        std::shared_ptr<PlainColumnTable> rhs,
                        const SIMDPlainGenericExpression& join_condition,
                        const std::string& fk_join_key,
                        const std::string& pk_join_key,
                        int foreign_key_input = 0);

        std::shared_ptr<ColumnTableBase<bool>> runSelf() override;

        // Method to get precomputed plaintext cache (for hybrid approach)
        std::vector<std::vector<std::vector<PlainField>>> getPrecomputedCache(const size_t chunk_size);

        OperatorType getType() const override;

        std::string getParameters() const override {
            return "FK=" + fk_join_key_name_ + ", PK=" + pk_join_key_name_ +
                   ", FK_input=" + std::to_string(foreign_key_input_);
        }

        void updateCollation() override {
            // For now, no collation updates needed
        }

        // Static methods to control debug output
        static void setDebugEnabled(bool enabled) { debug_enabled_ = enabled; }
        static bool isDebugEnabled() { return debug_enabled_; }

        // FHE operation tracking methods
        static void resetFHEOperationCounts();
        static void trackEvalRotate();
        static void trackEvalMult();
        static void printFHEOperationCounts();

        // Per-data-flow depth tracking
        static uint32_t getMaxDepthForDataFlow(const std::string& flow_name);
        static void trackDataFlowDepth(const std::string& flow_name, uint32_t depth);
        static void resetDataFlowDepths();
    };

} // namespace vaultdb

#endif // _COLUMN_KEYED_JOIN_H_