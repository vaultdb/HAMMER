#ifndef _FHE_PROJECT_H_
#define _FHE_PROJECT_H_

#include <operators/columnar/column_operator.h>
#include <query_table/columnar/fhe_column_table.h>

namespace vaultdb {

class FheProject : public ColumnOperator<void> {
private:
    std::shared_ptr<FheColumnTable> input_;
    std::vector<int32_t> projected_ordinals_;
    std::vector<std::string> output_aliases_;

    static SortDefinition remapSortDefinition(const SortDefinition& child_sort,
                                              const std::vector<int32_t>& projected_ordinals);

public:
    FheProject(ColumnOperator<void>* child,
               const std::vector<int32_t>& projected_ordinals,
               const std::vector<std::string>& output_aliases = {});

    std::shared_ptr<ColumnTableBase<void>> runSelf() override;
    OperatorType getType() const override { return OperatorType::FHE_PROJECT; }
    std::string getParameters() const override;
    void updateCollation() override {}
};

} // namespace vaultdb

#endif // _FHE_PROJECT_H_
