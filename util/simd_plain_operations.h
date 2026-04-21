#ifndef SIMD_PLAIN_OPERATIONS_H_
#define SIMD_PLAIN_OPERATIONS_H_

#include <vector>
#include <algorithm>
#include <cmath>
#include <query_table/field/field.h>
#include <query_table/columnar/plain_column_chunk.h>

namespace vaultdb {

    // SIMD operations for PlainColumnChunk that mirror FHE operations

    /**
     * SIMD version of EvalRotate - rotates a PlainColumnChunk by the specified amount
     */
    std::shared_ptr<PlainColumnChunk> plainEvalRotate(
            const std::shared_ptr<PlainColumnChunk>& chunk,
            int rotation_amount);

    /**
     * SIMD version of EvalMult - element-wise multiplication of two PlainColumnChunks
     */
    std::shared_ptr<PlainColumnChunk> plainEvalMult(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs);

    /**
     * SIMD version of EvalAdd - element-wise addition of two PlainColumnChunks
     */
    std::shared_ptr<PlainColumnChunk> plainEvalAdd(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs);

    /**
     * SIMD version of EvalSub - element-wise subtraction of two PlainColumnChunks
     */
    std::shared_ptr<PlainColumnChunk> plainEvalSub(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs);

    /**
     * SIMD version of rotateByBinaryDecomposition - rotates using binary decomposition
     */
    std::shared_ptr<PlainColumnChunk> plainRotateByBinaryDecomposition(
            const std::shared_ptr<PlainColumnChunk>& chunk,
            int rotation_amount,
            uint32_t slot_size);

    /**
     * SIMD version of comp_equal - element-wise equality comparison
     */
    std::shared_ptr<PlainColumnChunk> plainCompEqual(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs);

    /**
     * SIMD version of comp_not - element-wise NOT operation
     */
    std::shared_ptr<PlainColumnChunk> plainCompNot(
            const std::shared_ptr<PlainColumnChunk>& chunk);

    /**
     * SIMD version of comp_or - element-wise OR operation
     */
    std::shared_ptr<PlainColumnChunk> plainCompOr(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs);

    /**
     * SIMD version of comp_and - element-wise AND operation
     */
    std::shared_ptr<PlainColumnChunk> plainCompAnd(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs);

    /**
     * SIMD version of comp_greater_than - element-wise greater than comparison
     */
    std::shared_ptr<PlainColumnChunk> plainCompGreaterThan(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs);

    /**
     * Helper function to convert PlainField vector to float vector
     */
    std::vector<float> plainFieldsToFloats(const std::vector<PlainField>& fields);

    /**
     * Helper function to convert float vector to PlainField vector
     */
    std::vector<PlainField> floatsToPlainFields(const std::vector<float>& floats);

} // namespace vaultdb

#endif // SIMD_PLAIN_OPERATIONS_H_