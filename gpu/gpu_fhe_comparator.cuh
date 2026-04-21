#ifndef GPU_FHE_COMPARATOR_CUH_
#define GPU_FHE_COMPARATOR_CUH_

#include "gpu_fhe_backend.cuh"
#include <vector>
#include <cstddef>
#include <cstdint>

namespace vaultdb {

// ============================================================================
// Comparison operator enum
// ============================================================================
enum class GpuCompareOp {
    LESS_EQUAL,
    GREATER_THAN,
    LESS_THAN,
    GREATER_EQUAL,
    EQUAL
};

// ============================================================================
// Result of per-digit atomic comparison
// ============================================================================
struct GpuComparatorResult {
    heongpu::Ciphertext<heongpu::Scheme::BFV> GT;
    heongpu::Ciphertext<heongpu::Scheme::BFV> LT;
    heongpu::Ciphertext<heongpu::Scheme::BFV> EQ;
};

// ============================================================================
// Radix decomposition
// ============================================================================

std::vector<int64_t> encodeRadix(int64_t value, size_t base, size_t digits);

std::vector<std::vector<int64_t>> buildRadixColumns(
        const std::vector<int64_t>& values,
        size_t base, size_t digits, size_t pack_slots);

// ============================================================================
// Ternary sign polynomial atomic comparator.
// Evaluates T(z) = c1*z + c3*z^3 + ... then extracts GT/LT/EQ.
// Supported radix bases: 2, 3, 4, 5, 7, 9.
// ============================================================================
GpuComparatorResult gpuAtomicComparator(
        heongpu::Ciphertext<heongpu::Scheme::BFV>& diff_cipher,
        size_t pack_slots, size_t radix_base, size_t channel = 0);

// ============================================================================
// Lexicographic combine: merge per-digit GT/LT + EQ into final result
// ============================================================================
heongpu::Ciphertext<heongpu::Scheme::BFV> gpuReduceLexicographicalTree(
        std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& primary_digits,
        std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& eq_digits,
        size_t channel = 0);

// ============================================================================
// Full polynomial comparison (ties everything together)
// ============================================================================

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonGt(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel = 0);

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonLe(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel = 0);

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonLt(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel = 0);

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonGe(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel = 0);

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonEqual(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel = 0);

} // namespace vaultdb

#endif // GPU_FHE_COMPARATOR_CUH_
