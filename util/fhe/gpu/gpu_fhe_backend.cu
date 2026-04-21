#include "gpu_fhe_backend.cuh"
#include <heongpu/heongpu.hpp>
#include <iostream>
#include <stdexcept>

namespace vaultdb {

using BfvContext   = heongpu::HEContext<heongpu::Scheme::BFV>;
using BfvSecretkey = heongpu::Secretkey<heongpu::Scheme::BFV>;
using BfvPublickey = heongpu::Publickey<heongpu::Scheme::BFV>;
using BfvRelinkey  = heongpu::Relinkey<heongpu::Scheme::BFV>;
using BfvGaloiskey = heongpu::Galoiskey<heongpu::Scheme::BFV>;
using BfvPlaintext = heongpu::Plaintext<heongpu::Scheme::BFV>;
using BfvCiphertext = heongpu::Ciphertext<heongpu::Scheme::BFV>;
using BfvEncoder   = heongpu::HEEncoder<heongpu::Scheme::BFV>;
using BfvKeygen    = heongpu::HEKeyGenerator<heongpu::Scheme::BFV>;
using BfvEncryptor = heongpu::HEEncryptor<heongpu::Scheme::BFV>;
using BfvDecryptor = heongpu::HEDecryptor<heongpu::Scheme::BFV>;
using BfvArithOp   = heongpu::HEArithmeticOperator<heongpu::Scheme::BFV>;
using BfvLogicOp   = heongpu::HELogicOperator<heongpu::Scheme::BFV>;

// ============================================================================
// Impl (pimpl) -- holds all HEonGPU objects behind the firewall
// ============================================================================
struct GpuFheBackend::Impl {
    GpuBfvParams params;

    BfvContext context;  // shared_ptr<HEContextImpl<BFV>>
    std::unique_ptr<BfvSecretkey> secret_key;
    std::unique_ptr<BfvPublickey> public_key;
    std::unique_ptr<BfvRelinkey>  relin_key;
    std::unique_ptr<BfvGaloiskey> galois_key;
    std::unique_ptr<BfvEncoder>   encoder;
    std::unique_ptr<BfvKeygen>    keygen;
    std::unique_ptr<BfvEncryptor> encryptor;
    std::unique_ptr<BfvDecryptor> decryptor;
    std::unique_ptr<BfvArithOp>   arith_op;
    std::unique_ptr<BfvLogicOp>   logic_op;
};

// ============================================================================
// Singleton
// ============================================================================
GpuFheBackend& GpuFheBackend::getInstance() {
    static GpuFheBackend instance;
    return instance;
}

GpuFheBackend::GpuFheBackend() : impl_(std::make_unique<Impl>()) {}
GpuFheBackend::~GpuFheBackend() = default;

// ============================================================================
// Initialization
// ============================================================================
void GpuFheBackend::initialize(const GpuBfvParams& params) {
    impl_->params = params;

    impl_->context = heongpu::GenHEContext<heongpu::Scheme::BFV>();
    impl_->context->set_poly_modulus_degree(params.poly_modulus_degree);
    impl_->context->set_coeff_modulus_default_values(1);
    impl_->context->set_plain_modulus(static_cast<int>(params.plain_modulus));
    impl_->context->generate();

    std::cout << "[GpuFheBackend] Context initialized: N="
              << params.poly_modulus_degree
              << " t=" << params.plain_modulus << std::endl;

    initialized_ = true;
}

void GpuFheBackend::generateKeys() {
    if (!initialized_) {
        throw std::runtime_error("GpuFheBackend::generateKeys: not initialized");
    }
    auto ctx = impl_->context;

    impl_->keygen = std::make_unique<BfvKeygen>(ctx);

    impl_->secret_key = std::make_unique<BfvSecretkey>(ctx);
    impl_->keygen->generate_secret_key(*impl_->secret_key);

    impl_->public_key = std::make_unique<BfvPublickey>(ctx);
    impl_->keygen->generate_public_key(*impl_->public_key, *impl_->secret_key);

    impl_->relin_key = std::make_unique<BfvRelinkey>(ctx);
    impl_->keygen->generate_relin_key(*impl_->relin_key, *impl_->secret_key);

    // Build rotation indices: powers of 2 in both directions (matches FheManager)
    std::vector<int> galois_steps;
    size_t batch = params().poly_modulus_degree / 2;
    for (size_t step = 1; step < batch; step *= 2) {
        galois_steps.push_back(static_cast<int>(step));
    }
    for (size_t step = 1; step <= batch; step *= 2) {
        galois_steps.push_back(-static_cast<int>(step));
    }
    // Merge any user-provided steps
    for (int s : impl_->params.galois_steps) {
        galois_steps.push_back(s);
    }

    impl_->galois_key = std::make_unique<BfvGaloiskey>(ctx, galois_steps);
    impl_->keygen->generate_galois_key(*impl_->galois_key, *impl_->secret_key);

    impl_->encoder   = std::make_unique<BfvEncoder>(ctx);
    impl_->encryptor = std::make_unique<BfvEncryptor>(ctx, *impl_->public_key);
    impl_->decryptor = std::make_unique<BfvDecryptor>(ctx, *impl_->secret_key);
    impl_->arith_op  = std::make_unique<BfvArithOp>(ctx, *impl_->encoder);
    impl_->logic_op  = std::make_unique<BfvLogicOp>(ctx, *impl_->encoder);

    std::cout << "[GpuFheBackend] Keys generated. Slots="
              << slotCount() << std::endl;
}

void GpuFheBackend::reset() {
    impl_ = std::make_unique<Impl>();
    initialized_ = false;
}

// ============================================================================
// Accessors
// ============================================================================
size_t GpuFheBackend::slotCount() const {
    return impl_->params.poly_modulus_degree / 2;
}

size_t GpuFheBackend::polyModulusDegree() const {
    return impl_->params.poly_modulus_degree;
}

uint64_t GpuFheBackend::plainModulus() const {
    return impl_->params.plain_modulus;
}

const GpuBfvParams& GpuFheBackend::params() const {
    return impl_->params;
}

// ============================================================================
// Encode / Decode
// ============================================================================
void* GpuFheBackend::encodePacked(const std::vector<uint64_t>& message) {
    auto* pt = new BfvPlaintext(impl_->context);
    impl_->encoder->encode(*pt, message);
    return static_cast<void*>(pt);
}

void* GpuFheBackend::encodePackedSigned(const std::vector<int64_t>& message) {
    auto* pt = new BfvPlaintext(impl_->context);
    impl_->encoder->encode(*pt, message);
    return static_cast<void*>(pt);
}

std::vector<uint64_t> GpuFheBackend::decodePacked(void* plaintext_handle) {
    auto* pt = static_cast<BfvPlaintext*>(plaintext_handle);
    std::vector<uint64_t> result;
    impl_->encoder->decode(result, *pt);
    return result;
}

std::vector<int64_t> GpuFheBackend::decodePackedSigned(void* plaintext_handle) {
    auto* pt = static_cast<BfvPlaintext*>(plaintext_handle);
    std::vector<int64_t> result;
    impl_->encoder->decode(result, *pt);
    return result;
}

// ============================================================================
// Encrypt / Decrypt
// ============================================================================
void* GpuFheBackend::encrypt(void* plaintext_handle) {
    auto* pt = static_cast<BfvPlaintext*>(plaintext_handle);
    auto* ct = new BfvCiphertext(impl_->context);
    impl_->encryptor->encrypt(*ct, *pt);
    return static_cast<void*>(ct);
}

void* GpuFheBackend::decrypt(void* ciphertext_handle) {
    auto* ct = static_cast<BfvCiphertext*>(ciphertext_handle);
    auto* pt = new BfvPlaintext(impl_->context);
    impl_->decryptor->decrypt(*pt, *ct);
    return static_cast<void*>(pt);
}

// ============================================================================
// Convenience: encrypt / decrypt int64 vectors end-to-end
// ============================================================================
void* GpuFheBackend::encryptVector(const std::vector<int64_t>& message) {
    void* pt = encodePackedSigned(message);
    void* ct = encrypt(pt);
    destroyPlaintext(pt);
    return ct;
}

std::vector<int64_t> GpuFheBackend::decryptVector(void* ciphertext_handle) {
    void* pt = decrypt(ciphertext_handle);
    auto result = decodePackedSigned(pt);
    destroyPlaintext(pt);
    return result;
}

// ============================================================================
// Arithmetic
// ============================================================================
void* GpuFheBackend::add(void* ct1, void* ct2) {
    auto* a = static_cast<BfvCiphertext*>(ct1);
    auto* b = static_cast<BfvCiphertext*>(ct2);
    auto* out = new BfvCiphertext(impl_->context);
    impl_->arith_op->add(*a, *b, *out);
    return static_cast<void*>(out);
}

void* GpuFheBackend::addInplace(void* ct1, void* ct2) {
    auto* a = static_cast<BfvCiphertext*>(ct1);
    auto* b = static_cast<BfvCiphertext*>(ct2);
    impl_->arith_op->add_inplace(*a, *b);
    return ct1;
}

void* GpuFheBackend::addPlain(void* ct, void* pt) {
    auto* c = static_cast<BfvCiphertext*>(ct);
    auto* p = static_cast<BfvPlaintext*>(pt);
    auto* out = new BfvCiphertext(impl_->context);
    impl_->arith_op->add_plain(*c, *p, *out);
    return static_cast<void*>(out);
}

void* GpuFheBackend::sub(void* ct1, void* ct2) {
    auto* a = static_cast<BfvCiphertext*>(ct1);
    auto* b = static_cast<BfvCiphertext*>(ct2);
    auto* out = new BfvCiphertext(impl_->context);
    impl_->arith_op->sub(*a, *b, *out);
    return static_cast<void*>(out);
}

void* GpuFheBackend::subInplace(void* ct1, void* ct2) {
    auto* a = static_cast<BfvCiphertext*>(ct1);
    auto* b = static_cast<BfvCiphertext*>(ct2);
    impl_->arith_op->sub_inplace(*a, *b);
    return ct1;
}

void* GpuFheBackend::subPlain(void* ct, void* pt) {
    auto* c = static_cast<BfvCiphertext*>(ct);
    auto* p = static_cast<BfvPlaintext*>(pt);
    auto* out = new BfvCiphertext(impl_->context);
    impl_->arith_op->sub_plain(*c, *p, *out);
    return static_cast<void*>(out);
}

void* GpuFheBackend::multiply(void* ct1, void* ct2) {
    auto* a = static_cast<BfvCiphertext*>(ct1);
    auto* b = static_cast<BfvCiphertext*>(ct2);
    auto* out = new BfvCiphertext(impl_->context);
    impl_->arith_op->multiply(*a, *b, *out);
    impl_->arith_op->relinearize_inplace(*out, *impl_->relin_key);
    return static_cast<void*>(out);
}

void* GpuFheBackend::multiplyInplace(void* ct1, void* ct2) {
    auto* a = static_cast<BfvCiphertext*>(ct1);
    auto* b = static_cast<BfvCiphertext*>(ct2);
    impl_->arith_op->multiply_inplace(*a, *b);
    impl_->arith_op->relinearize_inplace(*a, *impl_->relin_key);
    return ct1;
}

void* GpuFheBackend::multiplyPlain(void* ct, void* pt) {
    auto* c = static_cast<BfvCiphertext*>(ct);
    auto* p = static_cast<BfvPlaintext*>(pt);
    auto* out = new BfvCiphertext(impl_->context);
    impl_->arith_op->multiply_plain(*c, *p, *out);
    return static_cast<void*>(out);
}

void* GpuFheBackend::negate(void* ct) {
    auto* c = static_cast<BfvCiphertext*>(ct);
    auto* out = new BfvCiphertext(impl_->context);
    impl_->arith_op->negate(*c, *out);
    return static_cast<void*>(out);
}

// ============================================================================
// Rotation
// ============================================================================
void* GpuFheBackend::rotateRows(void* ct, int shift) {
    auto* c = static_cast<BfvCiphertext*>(ct);
    auto* out = new BfvCiphertext(impl_->context);
    impl_->arith_op->rotate_rows(*c, *out, *impl_->galois_key, shift);
    return static_cast<void*>(out);
}

void* GpuFheBackend::rotateRowsInplace(void* ct, int shift) {
    auto* c = static_cast<BfvCiphertext*>(ct);
    impl_->arith_op->rotate_rows_inplace(*c, *impl_->galois_key, shift);
    return ct;
}



// 1 - (lhs - rhs)^2
BfvCiphertext gpu_comp_equal(BfvCiphertext& lhs, BfvCiphertext& rhs,
                             GpuFheBackend::Impl* impl) {
    BfvCiphertext diff(impl->context);
    impl->arith_op->sub(lhs, rhs, diff);

    BfvCiphertext sq(impl->context);
    impl->arith_op->multiply(diff, diff, sq);
    impl->arith_op->relinearize_inplace(sq, *impl->relin_key);

    BfvCiphertext out(impl->context);
    impl->logic_op->NOT(sq, out);
    return out;
}

// (lhs - rhs)^2
BfvCiphertext gpu_comp_greater_than_modular(BfvCiphertext& lhs, BfvCiphertext& rhs,
                                            GpuFheBackend::Impl* impl) {
    BfvCiphertext diff(impl->context);
    impl->arith_op->sub(lhs, rhs, diff);

    BfvCiphertext sq(impl->context);
    impl->arith_op->multiply(diff, diff, sq);
    impl->arith_op->relinearize_inplace(sq, *impl->relin_key);
    return sq;
}


// Polynomial comparison: greater-than for BFV with p=17 (base 64 radix)
// Mirrors bfv_compare_gt_p17 from fhe_comparator.h
BfvCiphertext gpu_bfv_compare_gt_p17(BfvCiphertext& diff_cipher,
                                     BfvCiphertext& z_to_p_minus_1_out,
                                     GpuFheBackend::Impl* impl) {
    size_t pack_slots = impl->params.poly_modulus_degree / 2;

    // z^2, z^4, z^8, z^16 (repeated squaring)
    BfvCiphertext z2(impl->context);
    impl->arith_op->multiply(diff_cipher, diff_cipher, z2);
    impl->arith_op->relinearize_inplace(z2, *impl->relin_key);

    BfvCiphertext z4(impl->context);
    impl->arith_op->multiply(z2, z2, z4);
    impl->arith_op->relinearize_inplace(z4, *impl->relin_key);

    BfvCiphertext z8(impl->context);
    impl->arith_op->multiply(z4, z4, z8);
    impl->arith_op->relinearize_inplace(z8, *impl->relin_key);

    BfvCiphertext z16(impl->context);
    impl->arith_op->multiply(z8, z8, z16);
    impl->arith_op->relinearize_inplace(z16, *impl->relin_key);

    z_to_p_minus_1_out = z16;

    // Build leaves: (diff - 9), (diff - 10), ..., (diff - 16)
    std::vector<BfvCiphertext> leaves;
    leaves.reserve(8);
    for (int64_t a = 9; a <= 16; ++a) {
        std::vector<int64_t> val_vec(pack_slots, a);
        BfvPlaintext val_pt(impl->context);
        impl->encoder->encode(val_pt, val_vec);

        BfvCiphertext leaf(impl->context);
        impl->arith_op->sub_plain(diff_cipher, val_pt, leaf);
        leaves.push_back(std::move(leaf));
    }

    // Tree of multiplications: 8 leaves → 4 → 2 → 1
    std::vector<BfvCiphertext> level1;
    for (size_t i = 0; i < leaves.size(); i += 2) {
        BfvCiphertext prod(impl->context);
        impl->arith_op->multiply(leaves[i], leaves[i + 1], prod);
        impl->arith_op->relinearize_inplace(prod, *impl->relin_key);
        level1.push_back(std::move(prod));
    }

    std::vector<BfvCiphertext> level2;
    for (size_t i = 0; i < level1.size(); i += 2) {
        BfvCiphertext prod(impl->context);
        impl->arith_op->multiply(level1[i], level1[i + 1], prod);
        impl->arith_op->relinearize_inplace(prod, *impl->relin_key);
        level2.push_back(std::move(prod));
    }

    BfvCiphertext product(impl->context);
    impl->arith_op->multiply(level2[0], level2[1], product);
    impl->arith_op->relinearize_inplace(product, *impl->relin_key);

    // Raise indicator to power 16: product^2 → ^4 → ^8 → ^16
    BfvCiphertext ind_2(impl->context);
    impl->arith_op->multiply(product, product, ind_2);
    impl->arith_op->relinearize_inplace(ind_2, *impl->relin_key);

    BfvCiphertext ind_4(impl->context);
    impl->arith_op->multiply(ind_2, ind_2, ind_4);
    impl->arith_op->relinearize_inplace(ind_4, *impl->relin_key);

    BfvCiphertext ind_8(impl->context);
    impl->arith_op->multiply(ind_4, ind_4, ind_8);
    impl->arith_op->relinearize_inplace(ind_8, *impl->relin_key);

    BfvCiphertext indicator_powered(impl->context);
    impl->arith_op->multiply(ind_8, ind_8, indicator_powered);
    impl->arith_op->relinearize_inplace(indicator_powered, *impl->relin_key);

    // gt_result = indicator_powered * z^(p-1)
    BfvCiphertext gt_result(impl->context);
    impl->arith_op->multiply(indicator_powered, z_to_p_minus_1_out, gt_result);
    impl->arith_op->relinearize_inplace(gt_result, *impl->relin_key);

    return gt_result;
}

// Convenience wrapper: ct_a > ct_b
BfvCiphertext gpu_bfv_compare_gt(BfvCiphertext& ct_a, BfvCiphertext& ct_b,
                                 GpuFheBackend::Impl* impl) {
    BfvCiphertext diff(impl->context);
    impl->arith_op->sub(ct_a, ct_b, diff);

    BfvCiphertext z_to_p_minus_1(impl->context);
    return gpu_bfv_compare_gt_p17(diff, z_to_p_minus_1, impl);
}

// ============================================================================
// Handle lifetime
// ============================================================================
void GpuFheBackend::destroyCiphertext(void* ct) {
    delete static_cast<BfvCiphertext*>(ct);
}

void GpuFheBackend::destroyPlaintext(void* pt) {
    delete static_cast<BfvPlaintext*>(pt);
}

} // namespace vaultdb
