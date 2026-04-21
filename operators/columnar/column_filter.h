#ifndef _COLUMN_FILTER_H_
#define _COLUMN_FILTER_H_

#include <operators/columnar/column_operator.h>
#include <query_table/columnar/column_table_base.h>
#include <expression/simd/simd_generic_expression.h>

namespace vaultdb {

    template<typename  B>
    class ColumnFilter : public ColumnOperator<B> {
    private:
        std::shared_ptr<PlainColumnTable> input_;
        SIMDPlainGenericExpression predicate_;

    public:
        ColumnFilter(std::shared_ptr<PlainColumnTable> input,
                     const SIMDPlainGenericExpression& pred)
                : input_(std::move(input)), predicate_(pred) {}

        std::shared_ptr<ColumnTableBase<void>> run() override {
            auto output = std::make_shared<PlainColumnTable>(input_->getSchema(), 0);
            const size_t chunk_count = input_->getChunkCount();

            for (size_t i = 0; i < chunk_count; ++i) {
                auto mask_chunk = predicate_.call(input_.get(), i);
                auto masked_row_count = mask_chunk->size();

                for (const auto& [name, col_ptr] : input_->getColumns()) {
                    auto plain_col = std::dynamic_pointer_cast<PlainColumn>(col_ptr);
                    auto input_chunk = plain_col->getConcretePlainChunks()[i];
                    auto masked_chunk = input_chunk->applyMask(mask_chunk);
                    output->addMaskedChunk(name, masked_chunk);
                }
            }

            return output;
        }

        OperatorType getType() const override { return OperatorType::FILTER; }
        std::string getParameters() const override { return "SIMD Plain Filter"; }
        void updateCollation() override {}
    };

}  // namespace vaultdb

#endif  // _COLUMN_FILTER_H_