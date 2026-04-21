#ifndef _FHE_SQL_INPUT_H_
#define _FHE_SQL_INPUT_H_

#include <operators/columnar/column_operator.h>
#include <query_table/columnar/fhe_column_table.h>
#include <data/psql_data_provider.h>
#include <util/system_configuration.h>
#include <query_table/query_schema.h>

namespace vaultdb {

    class FheSqlInput : public ColumnOperator<void> {
    private:
        std::string original_input_query_;
        std::string input_query_;
        std::string db_name_;
        size_t tuple_limit_;
        std::unique_ptr<PlainColumnTable> plain_input_;
        bool bin_flag_;
        std::vector<int32_t> bin_group_by_ordinals_;
        void runQuery();
        void createBinMetadata(std::shared_ptr<FheColumnTable> output_table, 
                              std::shared_ptr<PlainColumnTable> plain_snapshot);

    public:
        FheSqlInput(const std::string &db, const std::string &sql,
                    const SortDefinition &sort_def = {}, size_t tuple_limit = 0,
                    size_t output_cardinality = 0,
                    bool bin_flag = false,
                    const std::vector<int32_t>& bin_group_by_ordinals = {});

        FheSqlInput(const FheSqlInput& src);

        ~FheSqlInput() override = default;

        std::shared_ptr<ColumnTableBase<void>> runSelf() override;

        OperatorType getType() const override;
        std::string getParameters() const override;
        FheSqlInput* clone() const;

        bool operator==(const ColumnOperator& rhs) const;

        void updateCollation() override;

        std::string getInputQuery() const { return input_query_; }
        void setInputQuery(const std::string & sql) { input_query_ = sql; }
        std::string getDbName() const { return db_name_; }
        size_t getTupleLimit() const { return tuple_limit_; }
        const QuerySchema& getOutputSchema() const { return this->output_schema_; } // Ensure using base's member
        size_t getOutputCardinality() const { return output_cardinality_; }
        bool getBinFlag() const { return bin_flag_; }
        const std::vector<int32_t>& getBinGroupByOrdinals() const { return bin_group_by_ordinals_; }
    };

} // namespace vaultdb

#endif // _FHE_SQL_INPUT_H_
