#pragma once

#include <operators/columnar/column_operator.h>
#include <operators/operator.h>
#include <common/defs.h>
#include <query_table/query_table.h>

namespace vaultdb {

class MpcHostingOperator : public ColumnOperator<void> {
    Operator<emp::Bit>* real_mpc_op_;

public:
    MpcHostingOperator(Operator<emp::Bit>* real_op, int op_id)
        : ColumnOperator<void>(SortDefinition{}, 0), real_mpc_op_(real_op) {
        setOperatorId(op_id);
    }

    std::shared_ptr<ColumnTableBase<void>> runSelf() override {
        QueryTable<emp::Bit>* mpc_result = real_mpc_op_->run();
        if (!mpc_result) return nullptr;
        return std::shared_ptr<ColumnTableBase<void>>(
            reinterpret_cast<ColumnTableBase<void>*>(mpc_result),
            [](ColumnTableBase<void>*) {}  // no-op deleter; operator retains ownership
        );
    }

    OperatorType getType() const override { return OperatorType::MPC_HOSTING; }
    std::string getParameters() const override { return "MpcHostingOperator(wraps MPC op)"; }
    void updateCollation() override {}
    std::string getTypeString() const override { return "MpcHostingOperator"; }

    Operator<emp::Bit>* getRealMpcOp() { return real_mpc_op_; }
    const Operator<emp::Bit>* getRealMpcOp() const { return real_mpc_op_; }
};

}  // namespace vaultdb
