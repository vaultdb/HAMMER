#ifndef _FHE_MPC_PARTY_A_H_
#define _FHE_MPC_PARTY_A_H_

#include <memory>
#include <string>
#include <vector>

#include "query_table/field/field_type.h"

namespace vaultdb {
class FheColumnTable;
class FheNetworkIO;
class FheManager;

/// Row-oriented MPC result (column-major values). No PlainTable/ColumnTable.
struct MpcReconstructedRowData {
    std::vector<int64_t> values;
    std::vector<std::string> field_names;
    std::vector<std::string> table_names;  // table per column, for enum lookup during validation
    std::vector<FieldType> field_types;
    std::vector<int> string_lengths;
    size_t row_count = 0;
    int field_count = 0;
    /// Number of group-by columns (columns [0, group_by_count) are group keys; [group_by_count, field_count) are aggregates).
    int group_by_count = 0;
};

void ValidateTpchPartyAResults(
    const std::shared_ptr<FheColumnTable>& result_table,
    const std::string& unioned_db,
    const std::string& expected_query);

/// Compare MPC row data vs DataUtilities::getExpectedResults (row-by-row, no PlainTable for actual).
/// \param is_mpc_result true = from B+C (MPC): 1=dummy, 0=valid; false = from B only (FHE-only): 0=dummy, non-zero=valid.
void ValidateTpchPartyAResultsFromRowData(const MpcReconstructedRowData* data,
                                          const std::string& unioned_db,
                                          const std::string& expected_query,
                                          int sort_col_cnt,
                                          bool is_mpc_result = true);

/// Decrypt FHE table and convert to MpcReconstructedRowData (column-major) for unified validation.
std::unique_ptr<MpcReconstructedRowData> ConvertFheTableToRowData(
    const std::shared_ptr<FheColumnTable>& table,
    FheManager& manager);

/// Print Party A result table (reconstructed row data) to stdout for debugging.
/// \param is_mpc_result true = MPC: print only rows with dummy_tag==0 (valid); false = FHE-only: print only rows with dummy_tag>0 (valid).
void PrintPartyAResultTable(const MpcReconstructedRowData* data, bool is_mpc_result = true);

void DebugTpchPartyAMaskedDecrypt(FheNetworkIO* network_io);

/// Party A: receive metadata + shares from B and C, additive reconstruct (M = share_B + share_C).
/// \param validation if true, return row data for validation; else return nullptr.
std::unique_ptr<MpcReconstructedRowData> CollectSharesAndReconstruct(FheNetworkIO* bio, FheNetworkIO* cio, bool validation);
}  // namespace vaultdb

#endif  // _FHE_MPC_PARTY_A_H_
