#ifndef _COLUMN_SQL_INPUT_H_
#define _COLUMN_SQL_INPUT_H_

#include <operators/columnar/column_operator.h>
#include <query_table/columnar/column_table_base.h>
#include <string>
#include <memory>

namespace vaultdb {

    class ColumnSqlInput : public ColumnOperator<bool> {
    private:
        std::string sql_query_;
        std::string db_name_;
        bool has_dummy_tag_;

    public:
        ColumnSqlInput(const std::string& sql_query,
                       const std::string& db_name = "tpch_unioned_1500",
                       bool has_dummy_tag = true);

        std::shared_ptr<ColumnTableBase<bool>> runSelf() override;

        OperatorType getType() const override {
            return OperatorType::COLUMN_SQL_INPUT;
        }

        std::string getParameters() const override {
            return "SQL=" + sql_query_ + ", DB=" + db_name_;
        }

        void updateCollation() override {
            // No collation updates needed for input
        }
    };

} // namespace vaultdb

#endif // _COLUMN_SQL_INPUT_H_
