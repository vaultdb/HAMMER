#ifndef _FHE_AGGREGATE_H_
#define _FHE_AGGREGATE_H_

#include "openfhe.h"
#include <operators/columnar/column_operator.h>
#include <query_table/columnar/fhe_column_table.h>
#include <operators/support/aggregate_id.h>
#include <query_table/query_schema.h>
#include <string>
#include <vector>

namespace vaultdb {

    class FheAggregate : public ColumnOperator<void> {
    private:
        std::shared_ptr<FheColumnTable> input_;  // Cached input table (set in runSelf)
        std::vector<int32_t> group_by_ordinals_;  // Column ordinals for GROUP BY
        std::vector<ScalarAggregateDefinition> aggregate_definitions_;  // COUNT, SUM, etc.

    public:
        FheAggregate(ColumnOperator<void>* child,
                     const std::vector<ScalarAggregateDefinition>& aggregates,
                     const std::vector<int32_t>& group_by_ordinals = {});
        
        // Constructor accepting shared_ptr<FheColumnTable> directly (for testing convenience)
        FheAggregate(std::shared_ptr<FheColumnTable> input_table,
                     const std::vector<ScalarAggregateDefinition>& aggregates);

        std::shared_ptr<ColumnTableBase<void>> runSelf();

    private:
        // Efficient aggregation using bin metadata (when available)
        std::shared_ptr<ColumnTableBase<void>> runSelfWithBinMetadata();

        OperatorType getType() const override;

        std::string getParameters() const override;

        void updateCollation() override {}
    };

}  // namespace vaultdb

#endif  // _FHE_AGGREGATE_H_
