#ifndef _SIMD_GENERIC_EXPRESSION_H
#define _SIMD_GENERIC_EXPRESSION_H

#include <expression/simd/simd_expression_node.h>
#include <query_table/query_schema.h>
#include <query_table/columnar/plain_column_chunk.h>
#include <query_table/columnar/fhe_column_chunk.h>
#include <string>

namespace vaultdb {

    // A generic expression wrapper for SIMD-style columnar execution
    template<typename ChunkType>
    class SIMDGenericExpression {
    public:
        SIMDGenericExpression(std::shared_ptr<SIMDExpressionNode<ChunkType>> root,
                              const std::string& alias,
                              FieldType output_type)
                : root_(std::move(root)), alias_(alias), type_(output_type) {}

        SIMDGenericExpression(std::shared_ptr<SIMDExpressionNode<ChunkType>> root,
                              FieldType output_type)
                : root_(std::move(root)), alias_("anonymous"), type_(output_type) {}

        SIMDGenericExpression(const SIMDGenericExpression& src)
                : root_(src.root_->clone()), alias_(src.alias_), type_(src.type_) {}

        std::shared_ptr<ChunkType> call(const ColumnTableBase<void>* table, size_t chunk_idx) const {
            return root_->call(table, chunk_idx);
        }

        std::string getAlias() const {
            return alias_;
        }

        FieldType getType() const {
            return type_;
        }

        std::string toString() const {
            return root_->toString() + " : " + TypeUtilities::getTypeName(type_);
        }

        std::shared_ptr<SIMDGenericExpression<ChunkType>> clone() const {
            return std::make_shared<SIMDGenericExpression<ChunkType>>(root_->clone(), alias_, type_);
        }

    private:
        std::shared_ptr<SIMDExpressionNode<ChunkType>> root_;
        std::string alias_;
        FieldType type_;
    };

    using SIMDPlainGenericExpression = SIMDGenericExpression<PlainColumnChunk>;
    using SIMDFheGenericExpression = SIMDGenericExpression<FheColumnChunk>;


} // namespace vaultdb

#endif // _SIMD_GENERIC_EXPRESSION_H
