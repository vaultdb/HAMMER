#ifndef GPU_FHE_AGGREGATE_CUH_
#define GPU_FHE_AGGREGATE_CUH_

#include "gpu_fhe_backend.cuh"
#include "gpu_fhe_bin_metadata.cuh"
#include "gpu_fhe_column.cuh"
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace vaultdb {

// ============================================================================
// Rotate-and-add log-tree. Sums the first `range_length` slots of `ct` via
// ceil(log2(range_length)) rotate_rows + add pairs. After the call, every
// slot in [0, range_length) holds the full total; caller can read any one
// of them.
//
// Requires: slots of `ct` outside [0, range_length) must be zero (the
// masked plaintext in gpuAggregateSumChunk guarantees this). The zeros
// ensure wrap-around rotations contribute nothing, so no garbage leaks in.
//
// If range_length == 0, defaults to pack_slots (sum every slot). Early
// returns for range_length <= 1. Zero multiplicative depth consumed. Uses
// the per-channel Galois key for power-of-2 row rotations (already
// generated at backend init for steps 1, 2, 4, ..., pack_slots/2).
// ============================================================================
heongpu::Ciphertext<heongpu::Scheme::BFV>
gpuSumAllSlots(const heongpu::Ciphertext<heongpu::Scheme::BFV>& ct,
               size_t pack_slots,
               size_t range_length = 0,
               size_t channel = 0);

// ============================================================================
// gpuPrecomputeWeightedValue — hoisted precomputation of
// weighted = indicator * column_values, one multiply_plain per chunk per
// channel. Mirrors the batch-parallel weighted_value precomputation CPU
// does in fhe_aggregate.cpp around line 532 before its per-group loop, so
// the same weighted column can be reused across every group that touches
// this column.
//
// Inputs:
//  - indicator_col: filter indicator as a GpuFheColumn (1 = passes, 0 =
//    fails). Typically the output of the GPU filter pipeline.
//  - values_col: plaintext column values (one int64 per row) reduced mod
//    the channel's plain_modulus. values_col.size() must equal the total
//    row count of indicator_col (i.e. sum of packed_count over all chunks,
//    padding included as zeros).
//  - column_name: name stamped onto the returned GpuFheColumn so it can be
//    keyed into bin metadata downstream.
//
// Output: a new GpuFheColumn with one GpuFheColumnChunk per input chunk.
// Each chunk holds one ciphertext per channel. Consumes 1 multiplicative
// level from indicator_col (unchanged) into the returned column.
// ============================================================================
GpuFheColumn gpuPrecomputeWeightedValue(
        const GpuFheColumn& indicator_col,
        const std::vector<int64_t>& values_col,
        const std::string& column_name,
        size_t pack_slots);

// ============================================================================
// gpuAggregateGroupSum — per-group filtered SUM across all chunks that
// contain any of the group's rows. Returns a single ciphertext with the
// group's total isolated at `target_slot` (every other slot == 0), ready
// for the caller to EvalAdd into a per-(channel, column) output
// accumulator that packs multiple groups into one ciphertext.
//
// Algorithm (mirrors CPU processSumFused in fhe_aggregate.cpp:863):
//   1. For each chunk in group_metadata.column_bin_info[column_name]
//      .chunk_slot_ranges: apply a 0/1 range mask (EvalMult with a
//      plaintext that has 1 inside [start_slot, end_slot] and 0 elsewhere)
//      to a local copy of weighted_value_col's chunk. Track max_range_end.
//   2. evalAddMany over all masked per-chunk ciphertexts (tree of adds).
//      Safe because ranges in different chunks are disjoint by continuous
//      packing, so slot positions never collide.
//   3. One gpuSumAllSlots call with
//      range_length = max_range_end - target_slot + 1, placing the full
//      sum into a slot window that always includes target_slot.
//   4. EvalMult with cachedTargetMask(target_slot) so only target_slot
//      holds the real answer, rest become zero.
//
// Requires: weighted_value_col must already hold indicator * values (see
// gpuPrecomputeWeightedValue), the same column_name must appear in
// group_metadata.column_bin_info, and weighted_value_col must have at
// least 2 multiplicative levels remaining (one for the range mask, one
// for the target mask).
//
// Consumes: 2 multiplicative levels per call.
// ============================================================================
heongpu::Ciphertext<heongpu::Scheme::BFV> gpuAggregateGroupSum(
        const GpuFheColumn& weighted_value_col,
        const GpuBinGroupMetadata& group_metadata,
        const std::string& column_name,
        size_t target_slot,
        size_t pack_slots,
        size_t channel = 0);

// ============================================================================
// gpuAggregateGroupCount — per-group filtered COUNT across all chunks
// that contain any of the group's rows. Identical algorithm to
// gpuAggregateGroupSum but operates on the filter indicator directly: no
// precomputed weighted value needed, because counting the rows that
// passed the filter == summing the indicator ciphertexts.
//
// `column_name` is used only to look up chunk_slot_ranges in
// group_metadata.column_bin_info; any column in the metadata works under
// continuous packing because all columns share the same layout. The Q1
// test driver can pass any one aggregate column's name here.
//
// Consumes: 2 multiplicative levels per call (range mask + target mask).
// ============================================================================
heongpu::Ciphertext<heongpu::Scheme::BFV> gpuAggregateGroupCount(
        const GpuFheColumn& indicator_col,
        const GpuBinGroupMetadata& group_metadata,
        const std::string& column_name,
        size_t target_slot,
        size_t pack_slots,
        size_t channel = 0);

}  // namespace vaultdb

#endif  // GPU_FHE_AGGREGATE_CUH_
