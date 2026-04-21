#ifndef _SIMD_COMPARATOR_NODES_H
#define _SIMD_COMPARATOR_NODES_H

#include <expression/simd/simd_expression_node.h>
#include <query_table/columnar/plain_column_chunk.h>
#include <query_table/columnar/fhe_column_chunk.h>
#include <util/fhe/fhe_comparator.h>
#include <util/crypto_manager/fhe_manager.h>
#include <memory>
#include <vector>

namespace vaultdb {

    // Equal Node (default: Plain)
    template<typename ChunkType>
    class SIMDEqualNode : public BinarySIMDExpressionNode<ChunkType> {
    public:
        SIMDEqualNode(std::shared_ptr<SIMDExpressionNode<ChunkType>> lhs,
                      std::shared_ptr<SIMDExpressionNode<ChunkType>> rhs)
                : BinarySIMDExpressionNode<ChunkType>(std::move(lhs), std::move(rhs)) {}

        std::shared_ptr<ChunkType> call(const ColumnTableBase<void>* table, size_t chunk_idx) const override {
            auto lhs_val = this->lhs_->call(table, chunk_idx);
            auto rhs_val = this->rhs_->call(table, chunk_idx);
            return lhs_val->equals(rhs_val);
        }

        ExpressionKind kind() const override {
            return ExpressionKind::EQ;
        }

        std::string toString() const override {
            return "(EQ " + this->lhs_->toString() + ", " + this->rhs_->toString() + ")";
        }

        std::shared_ptr<SIMDExpressionNode<ChunkType>> clone() const override {
            return std::make_shared<SIMDEqualNode<ChunkType>>(this->lhs_->clone(), this->rhs_->clone());
        }
    };

    // FHE specialization for Equal
    template<>
    class SIMDEqualNode<FheColumnChunk> : public BinarySIMDExpressionNode<FheColumnChunk> {
    public:
        using Base = BinarySIMDExpressionNode<FheColumnChunk>;

        SIMDEqualNode(std::shared_ptr<SIMDExpressionNode<FheColumnChunk>> lhs,
                      std::shared_ptr<SIMDExpressionNode<FheColumnChunk>> rhs)
                : Base(std::move(lhs), std::move(rhs)) {}

        std::shared_ptr<FheColumnChunk> call(const ColumnTableBase<void>* table, size_t chunk_idx) const override {
            auto lhs_val = this->lhs_->call(table, chunk_idx);
            auto rhs_val = this->rhs_->call(table, chunk_idx);

            auto result = comp_equal(lhs_val->getCiphertext(), rhs_val->getCiphertext());
            return std::make_shared<FheColumnChunk>(result, lhs_val->q_params(), lhs_val->type_desc, lhs_val->packed_count);
        }

        ExpressionKind kind() const override {
            return ExpressionKind::EQ;
        }

        std::string toString() const override {
            return "(EQ " + this->lhs_->toString() + ", " + this->rhs_->toString() + ")";
        }

        std::shared_ptr<SIMDExpressionNode<FheColumnChunk>> clone() const override {
            return std::make_shared<SIMDEqualNode<FheColumnChunk>>(this->lhs_->clone(), this->rhs_->clone());
        }
    };

    // Plain specialization for Equal
    template<>
    class SIMDEqualNode<PlainColumnChunk> : public BinarySIMDExpressionNode<PlainColumnChunk> {
    public:
        using Base = BinarySIMDExpressionNode<PlainColumnChunk>;

        SIMDEqualNode(std::shared_ptr<SIMDExpressionNode<PlainColumnChunk>> lhs,
                      std::shared_ptr<SIMDExpressionNode<PlainColumnChunk>> rhs)
                : Base(std::move(lhs), std::move(rhs)) {}

        std::shared_ptr<PlainColumnChunk> call(const ColumnTableBase<void>* table, size_t chunk_idx) const override {
            auto lhs_val = this->lhs_->call(table, chunk_idx);
            auto rhs_val = this->rhs_->call(table, chunk_idx);

            // Elementwise equality
            size_t n = lhs_val->values.size();
            auto result = std::make_shared<PlainColumnChunk>(*lhs_val);
            result->values.resize(n);
            for (size_t i = 0; i < n; ++i) {
                result->values[i] = (lhs_val->values[i] == rhs_val->values[i]) ? 1.0 : 0.0;
            }
            return result;
        }

        ExpressionKind kind() const override {
            return ExpressionKind::EQ;
        }

        std::string toString() const override {
            return "(EQ " + this->lhs_->toString() + ", " + this->rhs_->toString() + ")";
        }

        std::shared_ptr<SIMDExpressionNode<PlainColumnChunk>> clone() const override {
            return std::make_shared<SIMDEqualNode<PlainColumnChunk>>(this->lhs_->clone(), this->rhs_->clone());
        }
    };

    // GreaterThan Node (default: Plain)
    template<typename ChunkType>
    class SIMDGreaterThanNode : public BinarySIMDExpressionNode<ChunkType> {
    public:
        SIMDGreaterThanNode(std::shared_ptr<SIMDExpressionNode<ChunkType>> lhs,
                            std::shared_ptr<SIMDExpressionNode<ChunkType>> rhs)
                : BinarySIMDExpressionNode<ChunkType>(std::move(lhs), std::move(rhs)) {}

        std::shared_ptr<ChunkType> call(const ColumnTableBase<void>* table, size_t chunk_idx) const override {
            auto lhs_val = this->lhs_->call(table, chunk_idx);
            auto rhs_val = this->rhs_->call(table, chunk_idx);
            return lhs_val->greaterThan(rhs_val);
        }

        ExpressionKind kind() const override {
            return ExpressionKind::GT;
        }

        std::string toString() const override {
            return "(GT " + this->lhs_->toString() + ", " + this->rhs_->toString() + ")";
        }

        std::shared_ptr<SIMDExpressionNode<ChunkType>> clone() const override {
            return std::make_shared<SIMDGreaterThanNode<ChunkType>>(this->lhs_->clone(), this->rhs_->clone());
        }
    };

    // FHE specialization for GreaterThan
    template<>
    class SIMDGreaterThanNode<FheColumnChunk> : public BinarySIMDExpressionNode<FheColumnChunk> {
    public:
        using Base = BinarySIMDExpressionNode<FheColumnChunk>;

        SIMDGreaterThanNode(std::shared_ptr<SIMDExpressionNode<FheColumnChunk>> lhs,
                            std::shared_ptr<SIMDExpressionNode<FheColumnChunk>> rhs)
                : Base(std::move(lhs), std::move(rhs)) {}

        std::shared_ptr<FheColumnChunk> call(const ColumnTableBase<void>* table, size_t chunk_idx) const override {
            auto lhs_val = this->lhs_->call(table, chunk_idx);
            auto rhs_val = this->rhs_->call(table, chunk_idx);

            auto result = comp_greater_than_modular(lhs_val->getCiphertext(), rhs_val->getCiphertext());
            return std::make_shared<FheColumnChunk>(result, lhs_val->q_params(), lhs_val->type_desc, lhs_val->packed_count);
        }

        ExpressionKind kind() const override {
            return ExpressionKind::GT;
        }

        std::string toString() const override {
            return "(GT " + this->lhs_->toString() + ", " + this->rhs_->toString() + ")";
        }

        std::shared_ptr<SIMDExpressionNode<FheColumnChunk>> clone() const override {
            return std::make_shared<SIMDGreaterThanNode<FheColumnChunk>>(this->lhs_->clone(), this->rhs_->clone());
        }
    };

    // Plain specialization for GreaterThan
    template<>
    class SIMDGreaterThanNode<PlainColumnChunk> : public BinarySIMDExpressionNode<PlainColumnChunk> {
    public:
        using Base = BinarySIMDExpressionNode<PlainColumnChunk>;

        SIMDGreaterThanNode(std::shared_ptr<SIMDExpressionNode<PlainColumnChunk>> lhs,
                            std::shared_ptr<SIMDExpressionNode<PlainColumnChunk>> rhs)
                : Base(std::move(lhs), std::move(rhs)) {}

        std::shared_ptr<PlainColumnChunk> call(const ColumnTableBase<void>* table, size_t chunk_idx) const override {
            auto lhs_val = this->lhs_->call(table, chunk_idx);
            auto rhs_val = this->rhs_->call(table, chunk_idx);

            size_t n = lhs_val->values.size();
            auto result = std::make_shared<PlainColumnChunk>(*lhs_val);
            result->values.resize(n);
            for (size_t i = 0; i < n; ++i) {
                result->values[i] = (lhs_val->values[i] > rhs_val->values[i]) ? 1.0 : 0.0;
            }
            return result;
        }

        ExpressionKind kind() const override {
            return ExpressionKind::GT;
        }

        std::string toString() const override {
            return "(GT " + this->lhs_->toString() + ", " + this->rhs_->toString() + ")";
        }

        std::shared_ptr<SIMDExpressionNode<PlainColumnChunk>> clone() const override {
            return std::make_shared<SIMDGreaterThanNode<PlainColumnChunk>>(this->lhs_->clone(), this->rhs_->clone());
        }
    };

    // Explicit instantiations
    using SIMDPlainEqualNode        = SIMDEqualNode<PlainColumnChunk>;
    using SIMDFheEqualNode          = SIMDEqualNode<FheColumnChunk>;

    using SIMDPlainGreaterThanNode  = SIMDGreaterThanNode<PlainColumnChunk>;
    using SIMDFheGreaterThanNode    = SIMDGreaterThanNode<FheColumnChunk>;

} // namespace vaultdb

#endif // _SIMD_COMPARATOR_NODES_H
