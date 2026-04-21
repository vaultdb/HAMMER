#include "gpu_fhe_backend.cuh"
#include <iostream>
#include <stdexcept>

namespace vaultdb {

// ============================================================================
// ChannelData -- one independent BFV context + keys + operators
// ============================================================================
struct ChannelData {
    uint64_t plain_modulus = 0;

    heongpu::HEContext<heongpu::Scheme::BFV>                  context;
    std::unique_ptr<heongpu::Secretkey<heongpu::Scheme::BFV>> secret_key;
    std::unique_ptr<heongpu::Publickey<heongpu::Scheme::BFV>> public_key;
    std::unique_ptr<heongpu::Relinkey<heongpu::Scheme::BFV>>  relin_key;
    std::unique_ptr<heongpu::Galoiskey<heongpu::Scheme::BFV>> galois_key;
    std::unique_ptr<heongpu::HEKeyGenerator<heongpu::Scheme::BFV>>       keygen;
    std::unique_ptr<heongpu::HEEncoder<heongpu::Scheme::BFV>>            encoder;
    std::unique_ptr<heongpu::HEEncryptor<heongpu::Scheme::BFV>>          encryptor;
    std::unique_ptr<heongpu::HEDecryptor<heongpu::Scheme::BFV>>          decryptor;
    std::unique_ptr<heongpu::HEArithmeticOperator<heongpu::Scheme::BFV>> arith_op;
    std::unique_ptr<heongpu::HELogicOperator<heongpu::Scheme::BFV>>      logic_op;
};

// ============================================================================
// Impl -- holds params + vector of RNS channels
// ============================================================================
struct GpuFheBackend::Impl {
    GpuBfvParams params;
    std::vector<std::unique_ptr<ChannelData>> channels;

    ChannelData& ch(size_t idx) {
        if (idx >= channels.size())
            throw std::out_of_range("GpuFheBackend: channel index " +
                                    std::to_string(idx) + " out of range (have " +
                                    std::to_string(channels.size()) + ")");
        return *channels[idx];
    }
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
    impl_->channels.clear();

    std::vector<uint64_t> moduli = params.rns_moduli;
    if (moduli.empty()) {
        moduli.push_back(params.plain_modulus);
    }

    for (size_t i = 0; i < moduli.size(); ++i) {
        auto cd = std::make_unique<ChannelData>();
        cd->plain_modulus = moduli[i];

        cd->context = heongpu::GenHEContext<heongpu::Scheme::BFV>();
        cd->context->set_poly_modulus_degree(params.poly_modulus_degree);
        cd->context->set_coeff_modulus_default_values(1);
        cd->context->set_plain_modulus(static_cast<int>(moduli[i]));
        cd->context->generate();

        std::cout << "[GpuFheBackend] Channel " << i << " context initialized: N="
                  << params.poly_modulus_degree
                  << " t=" << moduli[i] << std::endl;

        impl_->channels.push_back(std::move(cd));
    }

    initialized_ = true;
}

static void generateKeysForChannel(ChannelData& cd, const GpuBfvParams& params) {
    auto ctx = cd.context;

    cd.keygen = std::make_unique<heongpu::HEKeyGenerator<heongpu::Scheme::BFV>>(ctx);

    cd.secret_key = std::make_unique<heongpu::Secretkey<heongpu::Scheme::BFV>>(ctx);
    cd.keygen->generate_secret_key(*cd.secret_key);

    cd.public_key = std::make_unique<heongpu::Publickey<heongpu::Scheme::BFV>>(ctx);
    cd.keygen->generate_public_key(*cd.public_key, *cd.secret_key);

    cd.relin_key = std::make_unique<heongpu::Relinkey<heongpu::Scheme::BFV>>(ctx);
    cd.keygen->generate_relin_key(*cd.relin_key, *cd.secret_key);

    std::vector<int> galois_steps;
    size_t batch = params.poly_modulus_degree / 2;
    for (size_t step = 1; step < batch; step *= 2)
        galois_steps.push_back(static_cast<int>(step));
    for (size_t step = 1; step <= batch; step *= 2)
        galois_steps.push_back(-static_cast<int>(step));
    for (int s : params.galois_steps)
        galois_steps.push_back(s);

    cd.galois_key = std::make_unique<heongpu::Galoiskey<heongpu::Scheme::BFV>>(ctx, galois_steps);
    cd.keygen->generate_galois_key(*cd.galois_key, *cd.secret_key);

    cd.encoder   = std::make_unique<heongpu::HEEncoder<heongpu::Scheme::BFV>>(ctx);
    cd.encryptor = std::make_unique<heongpu::HEEncryptor<heongpu::Scheme::BFV>>(ctx, *cd.public_key);
    cd.decryptor = std::make_unique<heongpu::HEDecryptor<heongpu::Scheme::BFV>>(ctx, *cd.secret_key);
    cd.arith_op  = std::make_unique<heongpu::HEArithmeticOperator<heongpu::Scheme::BFV>>(ctx, *cd.encoder);
    cd.logic_op  = std::make_unique<heongpu::HELogicOperator<heongpu::Scheme::BFV>>(ctx, *cd.encoder);
}

void GpuFheBackend::generateKeys() {
    if (!initialized_)
        throw std::runtime_error("GpuFheBackend::generateKeys: not initialized");

    for (size_t i = 0; i < impl_->channels.size(); ++i) {
        std::cout << "[GpuFheBackend] Generating keys for channel " << i
                  << " (t=" << impl_->channels[i]->plain_modulus << ")..." << std::endl;
        generateKeysForChannel(*impl_->channels[i], impl_->params);
    }

    std::cout << "[GpuFheBackend] Keys generated for " << impl_->channels.size()
              << " channel(s). Slots=" << slotCount() << std::endl;
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

const GpuBfvParams& GpuFheBackend::params() const {
    return impl_->params;
}

size_t GpuFheBackend::channelCount() const {
    return impl_->channels.size();
}

// Channel 0 convenience (backward compat)
uint64_t GpuFheBackend::plainModulus() const            { return impl_->ch(0).plain_modulus; }
heongpu::HEContext<heongpu::Scheme::BFV>&            GpuFheBackend::context()    { return impl_->ch(0).context; }
heongpu::HEEncoder<heongpu::Scheme::BFV>&            GpuFheBackend::encoder()    { return *impl_->ch(0).encoder; }
heongpu::HEEncryptor<heongpu::Scheme::BFV>&          GpuFheBackend::encryptor()  { return *impl_->ch(0).encryptor; }
heongpu::HEDecryptor<heongpu::Scheme::BFV>&          GpuFheBackend::decryptor()  { return *impl_->ch(0).decryptor; }
heongpu::HEArithmeticOperator<heongpu::Scheme::BFV>& GpuFheBackend::arithOp()    { return *impl_->ch(0).arith_op; }
heongpu::HELogicOperator<heongpu::Scheme::BFV>&      GpuFheBackend::logicOp()    { return *impl_->ch(0).logic_op; }
heongpu::Relinkey<heongpu::Scheme::BFV>&             GpuFheBackend::relinKey()   { return *impl_->ch(0).relin_key; }
heongpu::Galoiskey<heongpu::Scheme::BFV>&            GpuFheBackend::galoisKey()  { return *impl_->ch(0).galois_key; }

// Per-channel access
uint64_t GpuFheBackend::plainModulus(size_t ch) const                             { return impl_->ch(ch).plain_modulus; }
heongpu::HEContext<heongpu::Scheme::BFV>&            GpuFheBackend::context(size_t ch)    { return impl_->ch(ch).context; }
heongpu::HEEncoder<heongpu::Scheme::BFV>&            GpuFheBackend::encoder(size_t ch)    { return *impl_->ch(ch).encoder; }
heongpu::HEEncryptor<heongpu::Scheme::BFV>&          GpuFheBackend::encryptor(size_t ch)  { return *impl_->ch(ch).encryptor; }
heongpu::HEDecryptor<heongpu::Scheme::BFV>&          GpuFheBackend::decryptor(size_t ch)  { return *impl_->ch(ch).decryptor; }
heongpu::HEArithmeticOperator<heongpu::Scheme::BFV>& GpuFheBackend::arithOp(size_t ch)    { return *impl_->ch(ch).arith_op; }
heongpu::HELogicOperator<heongpu::Scheme::BFV>&      GpuFheBackend::logicOp(size_t ch)    { return *impl_->ch(ch).logic_op; }
heongpu::Relinkey<heongpu::Scheme::BFV>&             GpuFheBackend::relinKey(size_t ch)   { return *impl_->ch(ch).relin_key; }
heongpu::Galoiskey<heongpu::Scheme::BFV>&            GpuFheBackend::galoisKey(size_t ch)  { return *impl_->ch(ch).galois_key; }

// ============================================================================
// Legacy GPU comparison primitives (superseded by gpu_fhe_comparator;
// kept for backward compatibility, operate on channel 0)
// ============================================================================

heongpu::Ciphertext<heongpu::Scheme::BFV> gpu_comp_equal(
        heongpu::Ciphertext<heongpu::Scheme::BFV>& lhs,
        heongpu::Ciphertext<heongpu::Scheme::BFV>& rhs,
        GpuFheBackend::Impl* impl) {
    auto& cd = impl->ch(0);
    heongpu::Ciphertext<heongpu::Scheme::BFV> diff(cd.context);
    cd.arith_op->sub(lhs, rhs, diff);

    heongpu::Ciphertext<heongpu::Scheme::BFV> sq(cd.context);
    cd.arith_op->multiply(diff, diff, sq);
    cd.arith_op->relinearize_inplace(sq, *cd.relin_key);

    heongpu::Ciphertext<heongpu::Scheme::BFV> out(cd.context);
    cd.logic_op->NOT(sq, out);
    return out;
}

heongpu::Ciphertext<heongpu::Scheme::BFV> gpu_comp_greater_than_modular(
        heongpu::Ciphertext<heongpu::Scheme::BFV>& lhs,
        heongpu::Ciphertext<heongpu::Scheme::BFV>& rhs,
        GpuFheBackend::Impl* impl) {
    auto& cd = impl->ch(0);
    heongpu::Ciphertext<heongpu::Scheme::BFV> diff(cd.context);
    cd.arith_op->sub(lhs, rhs, diff);

    heongpu::Ciphertext<heongpu::Scheme::BFV> sq(cd.context);
    cd.arith_op->multiply(diff, diff, sq);
    cd.arith_op->relinearize_inplace(sq, *cd.relin_key);
    return sq;
}

} // namespace vaultdb
