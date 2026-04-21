#ifndef GPU_FHE_BIN_METADATA_CUH_
#define GPU_FHE_BIN_METADATA_CUH_

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace vaultdb {

// ============================================================================
// GpuColumnBinInfo — mirrors CPU ColumnBinInfo from fhe_column_table.h.
//
// Describes how a single group's rows for a single column are laid out
// across ciphertext chunks under continuous packing: which chunks contain
// any of the group's rows, how many real (non-padding) values in total,
// and the per-chunk inclusive slot range the group occupies.
//
// chunk_slot_ranges is keyed by chunk_idx and maps to (start_slot, end_slot)
// inclusive on both ends — same convention as CPU.
// ============================================================================
struct GpuColumnBinInfo {
    std::size_t start_chunk_idx;      // Starting chunk index for this bin
    std::size_t end_chunk_idx;        // Ending chunk index (inclusive) for this bin
    std::size_t total_packed_count;   // Total number of real data values (excluding padding)

    // Per-chunk slot range information for continuous packing.
    // Maps chunk_index -> (start_slot, end_slot) within that chunk.
    std::map<std::size_t, std::pair<std::size_t, std::size_t>> chunk_slot_ranges;
};

// ============================================================================
// GpuBinGroupMetadata — mirrors CPU BinGroupMetadata from fhe_column_table.h.
//
// Per-group metadata: the plaintext GROUP BY key values, per-column bin info,
// and the original row range the group occupies in the input.
//
// Note: CPU uses std::vector<PlainField> for group_key_values. PlainField
// is a CPU-side Field<bool> that would drag the full Field<> hierarchy into
// the GPU tree, so we use std::vector<int64_t> instead — the GPU tree's
// universal plaintext value type (char-valued keys like 'R' are encoded as
// their int64 code, e.g. 82).
// ============================================================================
struct GpuBinGroupMetadata {
    // Group key values (GROUP BY column values)
    std::vector<int64_t> group_key_values;

    // Bin information for each column (Key: column name)
    std::unordered_map<std::string, GpuColumnBinInfo> column_bin_info;

    // Original row range in the input data (for debugging/validation)
    std::size_t original_start_row;
    std::size_t original_end_row;
};

}  // namespace vaultdb

#endif  // GPU_FHE_BIN_METADATA_CUH_
