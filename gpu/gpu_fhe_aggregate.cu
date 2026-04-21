#include "gpu_fhe_aggregate.cuh"
#include "gpu_fhe_column.cuh"
#include "fhe_column_chunk.cuh"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace vaultdb {
namespace {

// ============================================================================
// Cache infrastructure — mirrors CPU's thread_local caches in
// fhe_aggregate.cpp:57-91. GPU aggregate is single-threaded so plain
// static maps suffice (no thread_local needed).
// ============================================================================

// --- cachedTargetMask (single-hot plaintext: 1 at target_slot, 0 elsewhere) ---
// CPU keys by (cc_ptr, target_slot, slots); we key by (channel, target_slot)
// since pack_slots is fixed for a given run and channel identifies the context.
struct TargetMaskKey {
    size_t channel;
    size_t target_slot;
    bool operator==(const TargetMaskKey& o) const {
        return channel == o.channel && target_slot == o.target_slot;
    }
};

struct TargetMaskKeyHash {
    size_t operator()(const TargetMaskKey& k) const noexcept {
        size_t h = std::hash<size_t>{}(k.channel);
        h ^= std::hash<size_t>{}(k.target_slot) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

static std::unordered_map<TargetMaskKey,
                          heongpu::Plaintext<heongpu::Scheme::BFV>,
                          TargetMaskKeyHash> g_targetmask_cache;

heongpu::Plaintext<heongpu::Scheme::BFV>&
cachedTargetMask(size_t channel, size_t target_slot, size_t pack_slots) {
    TargetMaskKey key{channel, target_slot};
    auto it = g_targetmask_cache.find(key);
    if (it != g_targetmask_cache.end()) return it->second;

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& encoder = backend.encoder(channel);

    std::vector<int64_t> mask(pack_slots, 0);
    mask[target_slot] = 1;
    heongpu::Plaintext<heongpu::Scheme::BFV> pt(ctx);
    encoder.encode(pt, mask);
    auto result = g_targetmask_cache.emplace(key, std::move(pt));
    return result.first->second;
}

// --- cachedZeroCi (encryption of all-zero plaintext) ---
// CPU keys by (cc_ptr, pk_ptr, slots); we key by channel.
static std::unordered_map<size_t,
                          heongpu::Ciphertext<heongpu::Scheme::BFV>> g_zeroci_cache;

heongpu::Ciphertext<heongpu::Scheme::BFV>
cachedZeroCi(size_t channel, size_t pack_slots) {
    auto it = g_zeroci_cache.find(channel);
    if (it != g_zeroci_cache.end()) return it->second;

    auto& backend   = GpuFheBackend::getInstance();
    auto& ctx       = backend.context(channel);
    auto& encoder   = backend.encoder(channel);
    auto& encryptor = backend.encryptor(channel);

    std::vector<int64_t> zeros(pack_slots, 0);
    heongpu::Plaintext<heongpu::Scheme::BFV> pt(ctx);
    encoder.encode(pt, zeros);
    heongpu::Ciphertext<heongpu::Scheme::BFV> ct(ctx);
    encryptor.encrypt(ct, pt);
    g_zeroci_cache.emplace(channel, ct);
    return ct;
}

// ============================================================================
// evalAddMany — tree-based pairwise add reduction. Mirrors CPU's
// evalAddMany lambda in fhe_aggregate.cpp:408-424, without OMP
// (GPU kernels are already parallel).
// ============================================================================
heongpu::Ciphertext<heongpu::Scheme::BFV>
evalAddMany(std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> cts,
            size_t channel) {
    if (cts.empty())
        throw std::runtime_error("gpu_fhe_aggregate: evalAddMany empty");

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& arith   = backend.arithOp(channel);

    while (cts.size() > 1) {
        size_t half = cts.size() / 2;
        std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> next;
        next.reserve(half + (cts.size() % 2));
        for (size_t i = 0; i < half; ++i) {
            heongpu::Ciphertext<heongpu::Scheme::BFV> sum(ctx);
            arith.add(cts[2 * i], cts[2 * i + 1], sum);
            next.push_back(std::move(sum));
        }
        if (cts.size() % 2 == 1)
            next.push_back(std::move(cts.back()));
        cts = std::move(next);
    }
    return std::move(cts[0]);
}

}  // anonymous namespace

// ============================================================================
// gpuSumAllSlots — log-tree rotate-and-add over the first `range_length`
// slots. Mirrors the CPU sumSlotsInRangeLength lambda in
// fhe_aggregate.cpp:381-398, just with HEonGPU primitives.
// ============================================================================
heongpu::Ciphertext<heongpu::Scheme::BFV>
gpuSumAllSlots(const heongpu::Ciphertext<heongpu::Scheme::BFV>& ct,
               size_t pack_slots,
               size_t range_length,
               size_t channel) {

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& arith   = backend.arithOp(channel);
    auto& gk      = backend.galoisKey(channel);

    // range_length == 0 is the "sum every slot" default.
    size_t L = (range_length == 0)
                   ? pack_slots
                   : std::min(range_length, pack_slots);

    // `ct` is const but rotate_rows/add want non-const inputs — make a
    // mutable local copy the loop can both read and overwrite.
    heongpu::Ciphertext<heongpu::Scheme::BFV> result = ct;

    // Single slot or empty range: nothing to sum, the value is already
    // sitting where the caller will read it.
    if (L <= 1) return result;

    // Classic log-tree: at iteration k, each slot in [0, L) holds the sum
    // of 2^k original slots. After ceil(log2(L)) iterations every slot in
    // [0, L) holds the full total. Galois keys for steps 1, 2, 4, ...,
    // pack_slots/2 are pre-generated per channel, so every `step` here is
    // covered.
    int levels = static_cast<int>(std::ceil(std::log2(static_cast<double>(L))));
    size_t step = 1;
    for (int lv = 0; lv < levels; ++lv, step *= 2) {
        heongpu::Ciphertext<heongpu::Scheme::BFV> rotated(ctx);
        arith.rotate_rows(result, rotated, gk, static_cast<int>(step));
        arith.add(result, rotated, result);
    }
    return result;
}

// ============================================================================
// gpuPrecomputeWeightedValue — hoisted precomputation of
// weighted = indicator * column_values for every chunk × every channel.
// Mirrors CPU batch-parallel precomputation in fhe_aggregate.cpp:532+.
//
// For each chunk, for each channel:
//   1. Extract the chunk's slice of raw values, reduce mod p_channel
//      (signed → [0, p) since HEonGPU won't auto-reduce).
//   2. Encode into a BFV plaintext.
//   3. multiply_plain(indicator_copy, values_pt, weighted).
//   4. Store in the output column's chunk.
//
// Returns a new GpuFheColumn with one GpuFheColumnChunk per input chunk.
// Each chunk holds one ciphertext per channel.
// ============================================================================
GpuFheColumn gpuPrecomputeWeightedValue(
        const GpuFheColumn& indicator_col,
        const std::vector<int64_t>& values_col,
        const std::string& column_name,
        size_t pack_slots) {

    auto& backend       = GpuFheBackend::getInstance();
    const size_t num_ch = backend.channelCount();
    const size_t num_chunks = indicator_col.size();

    GpuFheColumn out(column_name);

    for (size_t chunk_idx = 0; chunk_idx < num_chunks; ++chunk_idx) {
        const GpuFheColumnChunk& ind_chunk = indicator_col.getChunk(chunk_idx);
        std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> weighted_channels;
        weighted_channels.reserve(num_ch);

        for (size_t ch = 0; ch < num_ch; ++ch) {
            auto& ctx     = backend.context(ch);
            auto& encoder = backend.encoder(ch);
            auto& arith   = backend.arithOp(ch);
            const int64_t p = static_cast<int64_t>(backend.plainModulus(ch));

            // Build this chunk's slice of values, reduced mod p.
            std::vector<int64_t> chunk_values(pack_slots, 0);
            const size_t base  = chunk_idx * pack_slots;
            const size_t limit = std::min(pack_slots,
                (values_col.size() > base) ? (values_col.size() - base) : size_t(0));
            for (size_t slot = 0; slot < limit; ++slot) {
                int64_t v = values_col[base + slot];
                // Signed → [0, p): ((v % p) + p) % p
                int64_t r = v % p;
                if (r < 0) r += p;
                chunk_values[slot] = r;
            }

            // Encode masked values into a plaintext for this channel.
            heongpu::Plaintext<heongpu::Scheme::BFV> values_pt(ctx);
            encoder.encode(values_pt, chunk_values);

            // multiply_plain wants non-const input; local copy of indicator.
            heongpu::Ciphertext<heongpu::Scheme::BFV> ind_copy =
                ind_chunk.getCiphertext(ch);
            heongpu::Ciphertext<heongpu::Scheme::BFV> weighted(ctx);
            arith.multiply_plain(ind_copy, values_pt, weighted);

            weighted_channels.push_back(std::move(weighted));
        }

        out.addChunk(GpuFheColumnChunk(
            std::move(weighted_channels), ind_chunk.size()));
    }

    return out;
}

// ============================================================================
// gpuAggregateGroupSum — per-group filtered SUM across all chunks that
// contain any of the group's rows. Mirrors CPU processSumFused lambda in
// fhe_aggregate.cpp:863-925.
//
// Algorithm:
//   1. For each chunk in column_bin_info[column_name].chunk_slot_ranges:
//        mask weighted_value_col's chunk with 0/1 range mask.
//   2. evalAddMany all masked per-chunk ciphertexts.
//   3. gpuSumAllSlots with effective_len = max_range_end - target_slot + 1.
//   4. Isolate target_slot via cachedTargetMask.
//
// Returns a single ciphertext with the group's total at target_slot
// (every other slot == 0).
// ============================================================================
heongpu::Ciphertext<heongpu::Scheme::BFV> gpuAggregateGroupSum(
        const GpuFheColumn& weighted_value_col,
        const GpuBinGroupMetadata& group_metadata,
        const std::string& column_name,
        size_t target_slot,
        size_t pack_slots,
        size_t channel) {

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& encoder = backend.encoder(channel);
    auto& arith   = backend.arithOp(channel);

    // Look up this group's bin info for the requested column.
    auto col_it = group_metadata.column_bin_info.find(column_name);
    if (col_it == group_metadata.column_bin_info.end())
        throw std::runtime_error(
            "gpuAggregateGroupSum: column '" + column_name +
            "' not found in group metadata");
    const GpuColumnBinInfo& col_bin_info = col_it->second;

    // Step 1: for each chunk this group touches, apply a 0/1 range mask
    // and collect masked ciphertexts.
    size_t max_range_end = 0;
    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> chunks_to_combine;

    for (const auto& [chunk_idx, range] : col_bin_info.chunk_slot_ranges) {
        size_t range_start = range.first;
        size_t range_end   = range.second;  // inclusive
        max_range_end = std::max(max_range_end, range_end);

        bool is_full_chunk =
            (range_start == 0 && range_end == pack_slots - 1);

        // Non-const copy of the weighted-value ciphertext for this chunk.
        heongpu::Ciphertext<heongpu::Scheme::BFV> chunk_ct =
            weighted_value_col.getChunk(chunk_idx).getCiphertext(channel);

        if (!is_full_chunk) {
            // Build a 0/1 range mask: 1 inside [range_start, range_end], 0 outside.
            std::vector<int64_t> range_mask_vec(pack_slots, 0);
            for (size_t i = range_start; i <= range_end && i < pack_slots; ++i)
                range_mask_vec[i] = 1;

            heongpu::Plaintext<heongpu::Scheme::BFV> range_mask_pt(ctx);
            encoder.encode(range_mask_pt, range_mask_vec);

            heongpu::Ciphertext<heongpu::Scheme::BFV> masked(ctx);
            arith.multiply_plain(chunk_ct, range_mask_pt, masked);
            chunks_to_combine.push_back(std::move(masked));
        } else {
            chunks_to_combine.push_back(std::move(chunk_ct));
        }
    }

    // Handle edge case: group not present in any chunk.
    if (chunks_to_combine.empty())
        return cachedZeroCi(channel, pack_slots);

    // Step 2: evalAddMany across per-chunk masked ciphertexts.
    // Safe because continuous packing guarantees disjoint slot ranges.
    heongpu::Ciphertext<heongpu::Scheme::BFV> total_sum_ch =
        (chunks_to_combine.size() == 1)
            ? std::move(chunks_to_combine[0])
            : evalAddMany(std::move(chunks_to_combine), channel);

    // Step 3: sum slots with effective_len = max_range_end - target_slot + 1.
    // Mirrors CPU: fhe_aggregate.cpp:914.
    size_t effective_len =
        std::min(max_range_end - target_slot + 1, pack_slots);
    total_sum_ch = gpuSumAllSlots(total_sum_ch, pack_slots, effective_len, channel);

    // Step 4: isolate target_slot via cached single-hot mask.
    // Mirrors CPU: fhe_aggregate.cpp:920.
    heongpu::Plaintext<heongpu::Scheme::BFV>& mask_pt =
        cachedTargetMask(channel, target_slot, pack_slots);

    heongpu::Ciphertext<heongpu::Scheme::BFV> aligned_sum(ctx);
    arith.multiply_plain(total_sum_ch, mask_pt, aligned_sum);

    return aligned_sum;
}

// ============================================================================
// gpuAggregateGroupCount — per-group filtered COUNT across all chunks.
// Identical to gpuAggregateGroupSum but operates on the filter indicator
// directly (no pre-computed weighted value). Mirrors CPU processCountFused
// lambda in fhe_aggregate.cpp:813-860.
// ============================================================================
heongpu::Ciphertext<heongpu::Scheme::BFV> gpuAggregateGroupCount(
        const GpuFheColumn& indicator_col,
        const GpuBinGroupMetadata& group_metadata,
        const std::string& column_name,
        size_t target_slot,
        size_t pack_slots,
        size_t channel) {

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& encoder = backend.encoder(channel);
    auto& arith   = backend.arithOp(channel);

    // Look up this group's bin info for chunk_slot_ranges.
    auto col_it = group_metadata.column_bin_info.find(column_name);
    if (col_it == group_metadata.column_bin_info.end())
        throw std::runtime_error(
            "gpuAggregateGroupCount: column '" + column_name +
            "' not found in group metadata");
    const GpuColumnBinInfo& col_bin_info = col_it->second;

    // Step 1: for each chunk this group touches, apply a 0/1 range mask
    // to the indicator ciphertext. Identical to SUM's step 1 but
    // operates on indicator_col instead of weighted_value_col.
    size_t max_range_end = 0;
    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> chunks_to_combine;

    for (const auto& [chunk_idx, range] : col_bin_info.chunk_slot_ranges) {
        size_t range_start = range.first;
        size_t range_end   = range.second;  // inclusive
        max_range_end = std::max(max_range_end, range_end);

        bool is_full_chunk =
            (range_start == 0 && range_end == pack_slots - 1);

        // Non-const copy of the indicator ciphertext for this chunk.
        heongpu::Ciphertext<heongpu::Scheme::BFV> chunk_ct =
            indicator_col.getChunk(chunk_idx).getCiphertext(channel);

        if (!is_full_chunk) {
            // Build a 0/1 range mask: 1 inside [range_start, range_end], 0 outside.
            std::vector<int64_t> range_mask_vec(pack_slots, 0);
            for (size_t i = range_start; i <= range_end && i < pack_slots; ++i)
                range_mask_vec[i] = 1;

            heongpu::Plaintext<heongpu::Scheme::BFV> range_mask_pt(ctx);
            encoder.encode(range_mask_pt, range_mask_vec);

            heongpu::Ciphertext<heongpu::Scheme::BFV> masked(ctx);
            arith.multiply_plain(chunk_ct, range_mask_pt, masked);
            chunks_to_combine.push_back(std::move(masked));
        } else {
            chunks_to_combine.push_back(std::move(chunk_ct));
        }
    }

    // Handle edge case: group not present in any chunk.
    if (chunks_to_combine.empty())
        return cachedZeroCi(channel, pack_slots);

    // Step 2: evalAddMany across chunks.
    heongpu::Ciphertext<heongpu::Scheme::BFV> total_sum_ch =
        (chunks_to_combine.size() == 1)
            ? std::move(chunks_to_combine[0])
            : evalAddMany(std::move(chunks_to_combine), channel);

    // Step 3: sum slots.
    size_t effective_len =
        std::min(max_range_end - target_slot + 1, pack_slots);
    total_sum_ch = gpuSumAllSlots(total_sum_ch, pack_slots, effective_len, channel);

    // Step 4: isolate target_slot.
    heongpu::Plaintext<heongpu::Scheme::BFV>& mask_pt =
        cachedTargetMask(channel, target_slot, pack_slots);

    heongpu::Ciphertext<heongpu::Scheme::BFV> aligned_sum(ctx);
    arith.multiply_plain(total_sum_ch, mask_pt, aligned_sum);

    return aligned_sum;
}

}  // namespace vaultdb
