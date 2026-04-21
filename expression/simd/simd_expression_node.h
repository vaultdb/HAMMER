#ifndef _SIMD_EXPRESSION_NODE_H
#define _SIMD_EXPRESSION_NODE_H

#include <memory>
#include <string>
#include <expression/expression_kind.h>
#include <query_table/field/field.h>
#include <query_table/columnar/column_table_base.h>
#include <query_table/columnar/fhe_column_table.h>

namespace vaultdb {

    // Base SIMD expression node interface
    template<typename ChunkType>
    class SIMDExpressionNode {
    public:
        virtual ~SIMDExpressionNode() = default;

        virtual std::shared_ptr<ChunkType> call(const ColumnTableBase<void>* table, size_t chunk_idx) const = 0;
        virtual std::string toString() const = 0;
        virtual ExpressionKind kind() const = 0;
        virtual std::shared_ptr<SIMDExpressionNode<ChunkType>> clone() const = 0;
    };

    // Binary SIMD expression node (has lhs and rhs)
    template<typename ChunkType>
    class BinarySIMDExpressionNode : public SIMDExpressionNode<ChunkType> {
    public:
        BinarySIMDExpressionNode(std::shared_ptr<SIMDExpressionNode<ChunkType>> lhs,
                                 std::shared_ptr<SIMDExpressionNode<ChunkType>> rhs)
                : lhs_(std::move(lhs)), rhs_(std::move(rhs)) {}

    protected:
        std::shared_ptr<SIMDExpressionNode<ChunkType>> lhs_;
        std::shared_ptr<SIMDExpressionNode<ChunkType>> rhs_;
    };

    // Literal Node
    template<typename ChunkType>
    class SIMDLiteralNode : public SIMDExpressionNode<ChunkType> {
    public:
        explicit SIMDLiteralNode(std::shared_ptr<ChunkType> value) : value_(std::move(value)) {}

        std::shared_ptr<ChunkType> call(const ColumnTableBase<void>*, size_t) const override {
            return value_;
        }

        std::string toString() const override {
            return "SIMDLiteral";
        }

        ExpressionKind kind() const override {
            return ExpressionKind::LITERAL;
        }

        std::shared_ptr<SIMDExpressionNode<ChunkType>> clone() const override {
            return std::make_shared<SIMDLiteralNode<ChunkType>>(value_);
        }

    private:
        std::shared_ptr<ChunkType> value_;
    };

    // PackedInputReference node
    template<typename ChunkType>
    class SIMDPackedInputReference : public SIMDExpressionNode<ChunkType> {
    public:
        SIMDPackedInputReference(uint32_t col_idx, const QuerySchema& schema)
                : col_idx_(col_idx), field_desc_(schema.getField(col_idx)) {}

        std::shared_ptr<ChunkType> call(const ColumnTableBase<void>* table, size_t chunk_idx) const override {
            const auto* fhe_table = dynamic_cast<const FheColumnTable*>(table);
            if (!fhe_table) {
                throw std::runtime_error("SIMDPackedInputReference: table is not a FheColumnTable");
            }

            auto fhe_col = fhe_table->getFheColumn(field_desc_.getName());
            if (!fhe_col) {
                throw std::runtime_error("SIMDPackedInputReference: Column '" + field_desc_.getName() + "' not found");
            }

            auto chunk = std::dynamic_pointer_cast<ChunkType>(fhe_col->getConcreteChunk(chunk_idx));
            if (!chunk) {
                throw std::runtime_error("SIMDPackedInputReference: ChunkType cast failed");
            }

            return chunk;
        }

        std::string toString() const override {
            return "SIMDPackedInputReference[" + field_desc_.getName() + "]";
        }

        ExpressionKind kind() const override {
            return ExpressionKind::PACKED_INPUT_REF;
        }

        std::shared_ptr<SIMDExpressionNode<ChunkType>> clone() const override {
            QuerySchema single_field_schema;
            single_field_schema.putField(field_desc_);
            return std::make_shared<SIMDPackedInputReference<ChunkType>>(col_idx_, single_field_schema);
        }

    private:
        uint32_t col_idx_;
        QueryFieldDesc field_desc_;
    };

} // namespace vaultdb

#endif // _SIMD_EXPRESSION_NODE_H