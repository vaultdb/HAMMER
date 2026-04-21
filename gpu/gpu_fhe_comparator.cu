#include "gpu_fhe_comparator.cuh"
#include <stdexcept>
#include <unordered_map>
#include <array>

namespace vaultdb {
namespace {

// ============================================================================
// Ternary sign polynomial coefficients 
// ============================================================================

struct TernaryCoeffs {
    uint64_t modulus;
    std::vector<int64_t> odd_coeffs;  // c1, c3, c5, ...
};

// Keyed by radix_base; each entry has 3 TernaryCoeffs (one per RNS modulus)
static const std::unordered_map<size_t, std::array<TernaryCoeffs, 3>> ternary_coeffs_by_base = {
    {2, {{
        {1179649, {1}},
        {2752513, {1}},
        {8519681, {1}},
    }}},
    {3, {{
        {1179649, {983042, 196608}},
        {2752513, {2293762, 458752}},
        {8519681, {1419948, 7099734}},
    }}},
    {4, {{
        {1179649, {668469, 294912, 216269}},
        {2752513, {1009256, 688128, 1055130}},
        {8519681, {3691863, 2129920, 2697899}},
    }}},
    {5, {{
        {1179649, {794860, 352256, 199885, 1012298}},
        {2752513, {910952, 1739435, 1934405, 920235}},
        {8519681, {4604686, 6330596, 6366095, 8257667}},
    }}},
    {7, {{
        {1179649, {600635, 819437, 649831, 338601, 917391, 213053}},
        {2752513, {1024945, 550035, 2250275, 33346, 713349, 933077}},
        {8519681, {7040110, 5295481, 1474674, 7582502, 735447, 3430830}},
    }}},
    {9, {{
        {1179649, {339319, 558254, 195103, 569161, 195079, 223494, 1101601, 356937}},
        {2752513, {251872, 1932504, 93287, 771636, 945241, 44673, 2230032, 1988295}},
        {8519681, {7686888, 679978, 6536311, 5283866, 4296078, 8067457, 795370, 732777}},
    }}},
};

static const std::array<int64_t, 3> inv2_per_modulus = {
    589825,   // inv(2) mod 1179649
    1376257,  // inv(2) mod 2752513
    4259841,  // inv(2) mod 8519681
};

static size_t getModulusIndex(uint64_t p) {
    if (p == 1179649) return 0;
    if (p == 2752513) return 1;
    if (p == 8519681) return 2;
    throw std::runtime_error("gpuAtomicComparator: unsupported plaintext modulus " + std::to_string(p));
}

heongpu::Plaintext<heongpu::Scheme::BFV> encodeScalar(
        int64_t val, size_t pack_slots,
        heongpu::HEContext<heongpu::Scheme::BFV>& ctx,
        heongpu::HEEncoder<heongpu::Scheme::BFV>& encoder) {
    std::vector<int64_t> vec(pack_slots, val);
    heongpu::Plaintext<heongpu::Scheme::BFV> pt(ctx);
    encoder.encode(pt, vec);
    return pt;
}

} // anonymous namespace

// ============================================================================
// Radix decomposition
// ============================================================================

std::vector<int64_t> encodeRadix(int64_t value, size_t base, size_t digits) {
    std::vector<int64_t> encoded(digits, 0);
    int64_t current = value;
    for (size_t i = 0; i < digits; ++i) {
        encoded[i] = current % static_cast<int64_t>(base);
        current /= static_cast<int64_t>(base);
    }
    return encoded;
}

std::vector<std::vector<int64_t>> buildRadixColumns(
        const std::vector<int64_t>& values,
        size_t base, size_t digits, size_t pack_slots) {
    std::vector<std::vector<int64_t>> columns(digits);
    for (auto& column : columns) {
        column.resize(pack_slots, 0);
    }
    for (size_t slot = 0; slot < pack_slots; ++slot) {
        int64_t current = (slot < values.size()) ? values[slot] : 0;
        for (size_t i = 0; i < digits; ++i) {
            columns[i][slot] = current % static_cast<int64_t>(base);
            current /= static_cast<int64_t>(base);
        }
    }
    return columns;
}

// ============================================================================
// Ternary Sign Polynomial atomic comparator
//
// Evaluates odd polynomial T(z) = c1*z + c3*z^3 + c5*z^5 + ...
//   z > 0 (mod p) -> T = +1
//   z = 0         -> T = 0
//   z < 0 (mod p) -> T = -1 (= p-1)
//
// Then extracts GT, LT, EQ:
//   GT = (T + T^2) * inv(2) mod p
//   LT = (T^2 - T) * inv(2) mod p
//   EQ = 1 - T^2
// ============================================================================

GpuComparatorResult gpuAtomicComparator(
        heongpu::Ciphertext<heongpu::Scheme::BFV>& diff_cipher,
        size_t pack_slots, size_t radix_base, size_t channel) {

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& encoder = backend.encoder(channel);
    auto& arith   = backend.arithOp(channel);
    auto& relin   = backend.relinKey(channel);
    uint64_t p    = backend.plainModulus(channel);

    size_t mod_idx = getModulusIndex(p);
    int64_t inv2 = inv2_per_modulus[mod_idx];

    auto it = ternary_coeffs_by_base.find(radix_base);
    if (it == ternary_coeffs_by_base.end())
        throw std::runtime_error(
            "gpuAtomicComparator: no ternary coefficients for radix_base=" +
            std::to_string(radix_base));

    const auto& coeffs = it->second[mod_idx].odd_coeffs;
    size_t n_coeffs = coeffs.size();  // = radix_base - 1

    // ---- Phase A: Build odd power basis {z, z^3, z^5, ...} ----
    // z -> z^2 -> z^3=z^2*z -> z^5=z^3*z^2 -> z^7=z^5*z^2 -> ...
    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> odd_powers;
    odd_powers.reserve(n_coeffs);
    odd_powers.push_back(diff_cipher);  // z^1

    if (n_coeffs >= 2) {
        heongpu::Ciphertext<heongpu::Scheme::BFV> z_sq(ctx);
        arith.multiply(diff_cipher, diff_cipher, z_sq);
        arith.relinearize_inplace(z_sq, relin);

        heongpu::Ciphertext<heongpu::Scheme::BFV> z3(ctx);
        arith.multiply(z_sq, diff_cipher, z3);
        arith.relinearize_inplace(z3, relin);
        odd_powers.push_back(std::move(z3));  // z^3

        // z^5 = z^3 * z^2, z^7 = z^5 * z^2, ...
        for (size_t k = 2; k < n_coeffs; ++k) {
            heongpu::Ciphertext<heongpu::Scheme::BFV> zk(ctx);
            arith.multiply(odd_powers[k - 1], z_sq, zk);
            arith.relinearize_inplace(zk, relin);
            odd_powers.push_back(std::move(zk));
        }
    }

    // ---- Phase B: Evaluate T = sum(c_i * z^(2i+1)) ----
    heongpu::Ciphertext<heongpu::Scheme::BFV> T(ctx);
    bool first_term = true;
    for (size_t i = 0; i < n_coeffs; ++i) {
        auto coeff_pt = encodeScalar(coeffs[i], pack_slots, ctx, encoder);
        heongpu::Ciphertext<heongpu::Scheme::BFV> term(ctx);
        arith.multiply_plain(odd_powers[i], coeff_pt, term);
        if (first_term) {
            T = std::move(term);
            first_term = false;
        } else {
            arith.add(T, term, T);
        }
    }

    // ---- Phase C: T^2 = T * T ----
    heongpu::Ciphertext<heongpu::Scheme::BFV> T_sq(ctx);
    arith.multiply(T, T, T_sq);
    arith.relinearize_inplace(T_sq, relin);

    // ---- Phase D: Extract GT, LT, EQ (all ct-pt, zero ct-ct) ----

    // GT = (T + T^2) * inv(2) mod p
    heongpu::Ciphertext<heongpu::Scheme::BFV> T_plus_Tsq(ctx);
    arith.add(T, T_sq, T_plus_Tsq);
    auto inv2_pt = encodeScalar(inv2, pack_slots, ctx, encoder);
    heongpu::Ciphertext<heongpu::Scheme::BFV> GT(ctx);
    arith.multiply_plain(T_plus_Tsq, inv2_pt, GT);

    // LT = (T^2 - T) * inv(2) mod p
    heongpu::Ciphertext<heongpu::Scheme::BFV> Tsq_minus_T(ctx);
    arith.sub(T_sq, T, Tsq_minus_T);
    heongpu::Ciphertext<heongpu::Scheme::BFV> LT(ctx);
    arith.multiply_plain(Tsq_minus_T, inv2_pt, LT);

    // EQ = 1 - T^2
    auto ones_pt = encodeScalar(1, pack_slots, ctx, encoder);
    heongpu::Ciphertext<heongpu::Scheme::BFV> EQ(ctx);
    arith.sub_plain(T_sq, ones_pt, EQ);
    arith.negate_inplace(EQ);

    return {std::move(GT), std::move(LT), std::move(EQ)};
}

// ============================================================================
// Lexicographic tree merge 
// ============================================================================

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuReduceLexicographicalTree(
        std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& primary_digits,
        std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& eq_digits,
        size_t channel) {

    if (primary_digits.empty() || primary_digits.size() != eq_digits.size())
        throw std::runtime_error("gpuReduceLexicographicalTree: invalid digit vectors");
    if (primary_digits.size() == 1) return primary_digits[0];

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx   = backend.context(channel);
    auto& arith = backend.arithOp(channel);
    auto& relin = backend.relinKey(channel);

    struct LexNode {
        heongpu::Ciphertext<heongpu::Scheme::BFV> primary;
        heongpu::Ciphertext<heongpu::Scheme::BFV> eq;
    };

    std::vector<LexNode> current(primary_digits.size());
    for (size_t i = 0; i < primary_digits.size(); ++i) {
        current[i] = {std::move(primary_digits[i]), std::move(eq_digits[i])};
    }

    while (current.size() > 1) {
        std::vector<LexNode> next;
        next.reserve((current.size() + 1) / 2);
        for (size_t i = 0; i < current.size(); i += 2) {
            if (i + 1 < current.size()) {
                auto& lower  = current[i];
                auto& higher = current[i + 1];
                heongpu::Ciphertext<heongpu::Scheme::BFV> eq_times_primary(ctx);
                arith.multiply(higher.eq, lower.primary, eq_times_primary);
                arith.relinearize_inplace(eq_times_primary, relin);
                heongpu::Ciphertext<heongpu::Scheme::BFV> merged_primary(ctx);
                arith.add(higher.primary, eq_times_primary, merged_primary);
                heongpu::Ciphertext<heongpu::Scheme::BFV> merged_eq(ctx);
                arith.multiply(higher.eq, lower.eq, merged_eq);
                arith.relinearize_inplace(merged_eq, relin);
                next.push_back({std::move(merged_primary), std::move(merged_eq)});
            } else {
                next.push_back(std::move(current[i]));
            }
        }
        current = std::move(next);
    }
    return std::move(current[0].primary);
}

// ============================================================================
// Full polynomial comparisons 
// ============================================================================

static heongpu::Ciphertext<heongpu::Scheme::BFV> gpuComparisonGtInternal(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel) {

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& encoder = backend.encoder(channel);
    auto& arith   = backend.arithOp(channel);

    size_t num_digits = threshold_digit_ciphers.size();
    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> gt_digits;
    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> eq_digits;
    gt_digits.reserve(num_digits);
    eq_digits.reserve(num_digits);

    for (size_t i = 0; i < num_digits; ++i) {
        heongpu::Plaintext<heongpu::Scheme::BFV> plain(ctx);
        encoder.encode(plain, radix_columns[i]);
        heongpu::Ciphertext<heongpu::Scheme::BFV> thresh_copy = threshold_digit_ciphers[i];
        heongpu::Ciphertext<heongpu::Scheme::BFV> diff_i(ctx);
        arith.sub_plain(thresh_copy, plain, diff_i);
        arith.negate_inplace(diff_i);

        GpuComparatorResult result = gpuAtomicComparator(diff_i, pack_slots, radix_base, channel);
        gt_digits.push_back(std::move(result.GT));
        eq_digits.push_back(std::move(result.EQ));
    }

    return gpuReduceLexicographicalTree(gt_digits, eq_digits, channel);
}

static heongpu::Ciphertext<heongpu::Scheme::BFV> gpuComparisonLtInternal(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel) {

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& encoder = backend.encoder(channel);
    auto& arith   = backend.arithOp(channel);

    size_t num_digits = threshold_digit_ciphers.size();
    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> lt_digits;
    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> eq_digits;
    lt_digits.reserve(num_digits);
    eq_digits.reserve(num_digits);

    for (size_t i = 0; i < num_digits; ++i) {
        heongpu::Plaintext<heongpu::Scheme::BFV> plain(ctx);
        encoder.encode(plain, radix_columns[i]);
        heongpu::Ciphertext<heongpu::Scheme::BFV> thresh_copy = threshold_digit_ciphers[i];
        heongpu::Ciphertext<heongpu::Scheme::BFV> diff_i(ctx);
        arith.sub_plain(thresh_copy, plain, diff_i);
        arith.negate_inplace(diff_i);

        GpuComparatorResult result = gpuAtomicComparator(diff_i, pack_slots, radix_base, channel);
        lt_digits.push_back(std::move(result.LT));
        eq_digits.push_back(std::move(result.EQ));
    }

    return gpuReduceLexicographicalTree(lt_digits, eq_digits, channel);
}

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonGt(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel) {
    return gpuComparisonGtInternal(threshold_digit_ciphers, radix_columns, pack_slots, radix_base, channel);
}

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonLe(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel) {

    auto gt = gpuComparisonGtInternal(threshold_digit_ciphers, radix_columns, pack_slots, radix_base, channel);

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& arith   = backend.arithOp(channel);
    auto ones_pt = encodeScalar(1, pack_slots, ctx, backend.encoder(channel));
    heongpu::Ciphertext<heongpu::Scheme::BFV> result(ctx);
    arith.sub_plain(gt, ones_pt, result);
    arith.negate_inplace(result);
    return result;
}

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonLt(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel) {
    return gpuComparisonLtInternal(threshold_digit_ciphers, radix_columns, pack_slots, radix_base, channel);
}

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonGe(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel) {

    auto lt = gpuComparisonLtInternal(threshold_digit_ciphers, radix_columns, pack_slots, radix_base, channel);

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& arith   = backend.arithOp(channel);
    auto ones_pt = encodeScalar(1, pack_slots, ctx, backend.encoder(channel));
    heongpu::Ciphertext<heongpu::Scheme::BFV> result(ctx);
    arith.sub_plain(lt, ones_pt, result);
    arith.negate_inplace(result);
    return result;
}

heongpu::Ciphertext<heongpu::Scheme::BFV> gpuPolynomialComparisonEqual(
        const std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>>& threshold_digit_ciphers,
        const std::vector<std::vector<int64_t>>& radix_columns,
        size_t pack_slots, size_t radix_base, size_t channel) {

    auto& backend = GpuFheBackend::getInstance();
    auto& ctx     = backend.context(channel);
    auto& encoder = backend.encoder(channel);
    auto& arith   = backend.arithOp(channel);
    auto& relin   = backend.relinKey(channel);

    size_t num_digits = threshold_digit_ciphers.size();

    // First digit: compute diff, atomic comparator → EQ
    heongpu::Plaintext<heongpu::Scheme::BFV> plain0(ctx);
    encoder.encode(plain0, radix_columns[0]);
    heongpu::Ciphertext<heongpu::Scheme::BFV> thresh_copy0 = threshold_digit_ciphers[0];
    heongpu::Ciphertext<heongpu::Scheme::BFV> diff0(ctx);
    arith.sub_plain(thresh_copy0, plain0, diff0);

    GpuComparatorResult r0 = gpuAtomicComparator(diff0, pack_slots, radix_base, channel);
    heongpu::Ciphertext<heongpu::Scheme::BFV> eq_result = std::move(r0.EQ);

    // Subsequent digits: EQ *= digit_EQ
    for (size_t i = 1; i < num_digits; ++i) {
        heongpu::Plaintext<heongpu::Scheme::BFV> plain_i(ctx);
        encoder.encode(plain_i, radix_columns[i]);
        heongpu::Ciphertext<heongpu::Scheme::BFV> thresh_copy_i = threshold_digit_ciphers[i];
        heongpu::Ciphertext<heongpu::Scheme::BFV> diff_i(ctx);
        arith.sub_plain(thresh_copy_i, plain_i, diff_i);

        GpuComparatorResult ri = gpuAtomicComparator(diff_i, pack_slots, radix_base, channel);

        heongpu::Ciphertext<heongpu::Scheme::BFV> new_eq(ctx);
        arith.multiply(eq_result, ri.EQ, new_eq);
        arith.relinearize_inplace(new_eq, relin);
        eq_result = std::move(new_eq);
    }

    return eq_result;
}

} // namespace vaultdb
