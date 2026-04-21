#include "column_sql_input.h"
#include <data/psql_data_provider.h>
#include <util/system_configuration.h>
#include <chrono>

using namespace vaultdb;

ColumnSqlInput::ColumnSqlInput(const std::string& sql_query,
                               const std::string& db_name,
                               bool has_dummy_tag)
        : ColumnOperator<bool>(SortDefinition{}, 0),  // Will be set after loading
          sql_query_(sql_query),
          db_name_(db_name),
          has_dummy_tag_(has_dummy_tag) {
}

std::shared_ptr<ColumnTableBase<bool>> ColumnSqlInput::runSelf() {
    PsqlDataProvider provider;
    auto plain_table = provider.getQueryColumnTable(db_name_, sql_query_);

    // Convert to column table format
    this->output_ = std::make_shared<PlainColumnTable>(*plain_table);

    return this->output_;
}