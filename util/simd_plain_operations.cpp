#include "simd_plain_operations.h"
#include <stdexcept>

namespace vaultdb {

    // Helper functions
    std::vector<float> plainFieldsToFloats(const std::vector<PlainField>& fields) {
        std::vector<float> result;
        result.reserve(fields.size());
        for (const auto& field : fields) {
            switch (field.getType()) {
                case FieldType::BOOL:
                    result.push_back(field.getValue<bool>() ? 1.0f : 0.0f);
                    break;
                case FieldType::INT:
                    result.push_back(static_cast<float>(field.getValue<int32_t>()));
                    break;
                case FieldType::LONG:
                    result.push_back(static_cast<float>(field.getValue<int64_t>()));
                    break;
                case FieldType::FLOAT:
                    result.push_back(field.getValue<float>());
                    break;
                default:
                    throw std::runtime_error("Unsupported field type for conversion to float");
            }
        }
        return result;
    }

    std::vector<PlainField> floatsToPlainFields(const std::vector<float>& floats) {
        std::vector<PlainField> result;
        result.reserve(floats.size());
        for (float val : floats) {
            result.emplace_back(FieldType::FLOAT, val);
        }
        return result;
    }

    // SIMD EvalRotate - rotates a PlainColumnChunk by the specified amount
    std::shared_ptr<PlainColumnChunk> plainEvalRotate(
            const std::shared_ptr<PlainColumnChunk>& chunk,
            int rotation_amount) {

        if (!chunk) {
            throw std::invalid_argument("plainEvalRotate: Null chunk provided");
        }

        if (chunk->values.empty()) {
            return std::make_shared<PlainColumnChunk>(chunk->values);
        }

        if (rotation_amount == 0) {
            return std::make_shared<PlainColumnChunk>(chunk->values);
        }

        std::vector<PlainField> rotated_values = chunk->values;
        size_t size = chunk->values.size();

        // Normalize rotation amount to be within [0, size)
        rotation_amount = rotation_amount % static_cast<int>(size);
        if (rotation_amount < 0) {
            rotation_amount += static_cast<int>(size);
        }

        if (rotation_amount == 0) {
            return std::make_shared<PlainColumnChunk>(rotated_values);
        }

        // Perform the rotation
        std::rotate(rotated_values.begin(),
                    rotated_values.begin() + rotation_amount,
                    rotated_values.end());

        return std::make_shared<PlainColumnChunk>(rotated_values);
    }

    // SIMD EvalMult - element-wise multiplication
    std::shared_ptr<PlainColumnChunk> plainEvalMult(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs) {

        if (!lhs || !rhs) {
            throw std::invalid_argument("plainEvalMult: Null chunk provided");
        }

        if (lhs->values.size() != rhs->values.size()) {
            throw std::invalid_argument("plainEvalMult: Chunk sizes must match");
        }

        // Convert to float vectors for SIMD-style operations
        auto lhs_floats = plainFieldsToFloats(lhs->values);
        auto rhs_floats = plainFieldsToFloats(rhs->values);

        // SIMD-style multiplication
        std::vector<float> result_floats(lhs_floats.size());
        for (size_t i = 0; i < lhs_floats.size(); ++i) {
            result_floats[i] = lhs_floats[i] * rhs_floats[i];
        }

        // Convert back to PlainField
        auto result_values = floatsToPlainFields(result_floats);
        return std::make_shared<PlainColumnChunk>(result_values);
    }

    // SIMD EvalAdd - element-wise addition
    std::shared_ptr<PlainColumnChunk> plainEvalAdd(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs) {

        if (!lhs || !rhs) {
            throw std::invalid_argument("plainEvalAdd: Null chunk provided");
        }

        if (lhs->values.size() != rhs->values.size()) {
            throw std::invalid_argument("plainEvalAdd: Chunk sizes must match");
        }

        // Convert to float vectors for SIMD-style operations
        auto lhs_floats = plainFieldsToFloats(lhs->values);
        auto rhs_floats = plainFieldsToFloats(rhs->values);

        // SIMD-style addition
        std::vector<float> result_floats(lhs_floats.size());
        for (size_t i = 0; i < lhs_floats.size(); ++i) {
            result_floats[i] = lhs_floats[i] + rhs_floats[i];
        }

        // Convert back to PlainField
        auto result_values = floatsToPlainFields(result_floats);
        return std::make_shared<PlainColumnChunk>(result_values);
    }

    // SIMD EvalSub - element-wise subtraction
    std::shared_ptr<PlainColumnChunk> plainEvalSub(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs) {

        if (!lhs || !rhs) {
            throw std::invalid_argument("plainEvalSub: Null chunk provided");
        }

        if (lhs->values.size() != rhs->values.size()) {
            throw std::invalid_argument("plainEvalSub: Chunk sizes must match");
        }

        // Convert to float vectors for SIMD-style operations
        auto lhs_floats = plainFieldsToFloats(lhs->values);
        auto rhs_floats = plainFieldsToFloats(rhs->values);

        // SIMD-style subtraction
        std::vector<float> result_floats(lhs_floats.size());
        for (size_t i = 0; i < lhs_floats.size(); ++i) {
            result_floats[i] = lhs_floats[i] - rhs_floats[i];
        }

        // Convert back to PlainField
        auto result_values = floatsToPlainFields(result_floats);
        return std::make_shared<PlainColumnChunk>(result_values);
    }

    // SIMD rotateByBinaryDecomposition - rotates using binary decomposition
    std::shared_ptr<PlainColumnChunk> plainRotateByBinaryDecomposition(
            const std::shared_ptr<PlainColumnChunk>& chunk,
            int rotation_amount,
            uint32_t slot_size) {

        if (!chunk) {
            throw std::invalid_argument("plainRotateByBinaryDecomposition: Null chunk provided");
        }

        if (rotation_amount == 0) {
            return std::make_shared<PlainColumnChunk>(chunk->values);
        }

        // Normalize rotation amount to be within [0, slot_size)
        rotation_amount = rotation_amount % static_cast<int>(slot_size);
        if (rotation_amount < 0) {
            rotation_amount += static_cast<int>(slot_size);
        }

        if (rotation_amount == 0) {
            return std::make_shared<PlainColumnChunk>(chunk->values);
        }

        std::vector<PlainField> result = chunk->values;

        // Binary decomposition: apply power-of-2 rotations
        for (int power = 1; power <= static_cast<int>(slot_size/2); power *= 2) {
            if (rotation_amount & power) {  // If this bit is set in the rotation amount
                std::rotate(result.begin(), result.begin() + power, result.end());
            }
        }

        return std::make_shared<PlainColumnChunk>(result);
    }

    // SIMD comp_equal - element-wise equality comparison
    std::shared_ptr<PlainColumnChunk> plainCompEqual(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs) {

        if (!lhs || !rhs) {
            throw std::invalid_argument("plainCompEqual: Null chunk provided");
        }

        if (lhs->values.size() != rhs->values.size()) {
            throw std::invalid_argument("plainCompEqual: Chunk sizes must match");
        }

        // SIMD-style equality comparison
        std::vector<PlainField> result_values(lhs->values.size());
        for (size_t i = 0; i < lhs->values.size(); ++i) {
            bool is_equal = (lhs->values[i] == rhs->values[i]);
            result_values[i] = PlainField(FieldType::FLOAT, is_equal ? 1.0f : 0.0f);
        }

        return std::make_shared<PlainColumnChunk>(result_values);
    }

    // SIMD comp_not - element-wise NOT operation
    std::shared_ptr<PlainColumnChunk> plainCompNot(
            const std::shared_ptr<PlainColumnChunk>& chunk) {

        if (!chunk) {
            throw std::invalid_argument("plainCompNot: Null chunk provided");
        }

        // Convert to float for arithmetic operations
        auto chunk_floats = plainFieldsToFloats(chunk->values);

        // SIMD-style NOT operation (1.0 - value)
        std::vector<float> result_floats(chunk_floats.size());
        for (size_t i = 0; i < chunk_floats.size(); ++i) {
            result_floats[i] = 1.0f - chunk_floats[i];
        }

        // Convert back to PlainField
        auto result_values = floatsToPlainFields(result_floats);
        return std::make_shared<PlainColumnChunk>(result_values);
    }

    // SIMD comp_or - element-wise OR operation
    std::shared_ptr<PlainColumnChunk> plainCompOr(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs) {

        if (!lhs || !rhs) {
            throw std::invalid_argument("plainCompOr: Null chunk provided");
        }

        if (lhs->values.size() != rhs->values.size()) {
            throw std::invalid_argument("plainCompOr: Chunk sizes must match");
        }

        // Convert to float for arithmetic operations
        auto lhs_floats = plainFieldsToFloats(lhs->values);
        auto rhs_floats = plainFieldsToFloats(rhs->values);

        // SIMD-style OR operation: a + b - a*b
        std::vector<float> result_floats(lhs_floats.size());
        for (size_t i = 0; i < lhs_floats.size(); ++i) {
            result_floats[i] = lhs_floats[i] + rhs_floats[i] - lhs_floats[i] * rhs_floats[i];
        }

        // Convert back to PlainField
        auto result_values = floatsToPlainFields(result_floats);
        return std::make_shared<PlainColumnChunk>(result_values);
    }

    // SIMD comp_and - element-wise AND operation
    std::shared_ptr<PlainColumnChunk> plainCompAnd(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs) {

        if (!lhs || !rhs) {
            throw std::invalid_argument("plainCompAnd: Null chunk provided");
        }

        if (lhs->values.size() != rhs->values.size()) {
            throw std::invalid_argument("plainCompAnd: Chunk sizes must match");
        }

        // Convert to float for arithmetic operations
        auto lhs_floats = plainFieldsToFloats(lhs->values);
        auto rhs_floats = plainFieldsToFloats(rhs->values);

        // SIMD-style AND operation: a * b
        std::vector<float> result_floats(lhs_floats.size());
        for (size_t i = 0; i < lhs_floats.size(); ++i) {
            result_floats[i] = lhs_floats[i] * rhs_floats[i];
        }

        // Convert back to PlainField
        auto result_values = floatsToPlainFields(result_floats);
        return std::make_shared<PlainColumnChunk>(result_values);
    }

    // SIMD comp_greater_than - element-wise greater than comparison
    std::shared_ptr<PlainColumnChunk> plainCompGreaterThan(
            const std::shared_ptr<PlainColumnChunk>& lhs,
            const std::shared_ptr<PlainColumnChunk>& rhs) {

        if (!lhs || !rhs) {
            throw std::invalid_argument("plainCompGreaterThan: Null chunk provided");
        }

        if (lhs->values.size() != rhs->values.size()) {
            throw std::invalid_argument("plainCompGreaterThan: Chunk sizes must match");
        }

        // Convert to float for comparison
        auto lhs_floats = plainFieldsToFloats(lhs->values);
        auto rhs_floats = plainFieldsToFloats(rhs->values);

        // SIMD-style greater than comparison
        std::vector<PlainField> result_values(lhs_floats.size());
        for (size_t i = 0; i < lhs_floats.size(); ++i) {
            bool is_greater = (lhs_floats[i] > rhs_floats[i]);
            result_values[i] = PlainField(FieldType::FLOAT, is_greater ? 1.0f : 0.0f);
        }

        return std::make_shared<PlainColumnChunk>(result_values);
    }

} // namespace vaultdb