#ifndef _SIMD_EXPRESSION_H
#define _SIMD_EXPRESSION_H

#include <query_table/query_schema.h>
#include "expression/expression_kind.h"
#include <string>
#include <memory>

namespace vaultdb {


    // Base SIMD Expression Interface
    template<typename ChunkType>
    class SIMDExpression {
    protected:
        std::string alias_;
        FieldType type_;

    public:
        SIMDExpression() : alias_("anonymous"), type_(FieldType::INVALID) {}
        SIMDExpression(const std::string &alias, const FieldType &type) : alias_(alias), type_(type) {}
        virtual ~SIMDExpression() = default;

        virtual std::shared_ptr<void> call(const void* table) const = 0;
        virtual ExpressionKind kind() const = 0;
        virtual std::string toString() const = 0;
        virtual ExpressionClass exprClass() const = 0;
        virtual std::shared_ptr<SIMDExpression> clone() const = 0;

        std::string getAlias() const { return alias_; }
        FieldType getType() const { return type_; }
        void setAlias(const std::string &alias) { alias_ = alias; }
        void setType(const FieldType &type) { type_ = type; }
    };

} // namespace vaultdb

#endif //_SIMD_EXPRESSION_H
