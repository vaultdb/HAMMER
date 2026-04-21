#ifndef COLUMN_TO_ROW_ENCODER_H_
#define COLUMN_TO_ROW_ENCODER_H_

#include <memory>

#include "openfhe.h"
#include "query_table/query_table.h"
#include "query_table/columnar/fhe_column_table.h"

namespace vaultdb {

PlainTable* ColumnToRowEncode(
    const std::shared_ptr<FheColumnTable>& col_table,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk);

SecureTable* ColumnToSecureTableEncode(
    const std::shared_ptr<FheColumnTable>& col_table,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk);

PlainTable* SecretShareToPlainTable(
    const QuerySchema& schema,
    const std::shared_ptr<PlainColumnTable>& plain_snapshot,
    const std::vector<int64_t>& aggregate_values);

/// Multi-column variant: fill group-key columns from plain_snapshot and each
/// aggregate column from aggregate_values_per_column[i] (row-major) for schema
/// column indices agg_col_indices[i].
PlainTable* SecretShareToPlainTable(
    const QuerySchema& schema,
    const std::shared_ptr<PlainColumnTable>& plain_snapshot,
    const std::vector<std::vector<int64_t>>& aggregate_values_per_column,
    const std::vector<int>& agg_col_indices);

}  // namespace vaultdb

#endif  // COLUMN_TO_ROW_ENCODER_H_
