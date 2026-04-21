#ifndef GPU_FHE_BACKEND_CUH_
#define GPU_FHE_BACKEND_CUH_

#include <heongpu/heongpu.hpp>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>

namespace vaultdb {

enum class FheBackendType {
    CPU_OPENFHE,
    GPU_HEONGPU
};

struct GpuBfvParams {
    size_t poly_modulus_degree = 32768;
    uint64_t plain_modulus     = 1179649;
    uint32_t mult_depth        = 15;
    std::vector<int> galois_steps;

    // RNS moduli for multi-channel support (64-bit aggregation).
    // If non-empty, one HEonGPU context is created per modulus.
    // If empty, a single context is created using plain_modulus.
    std::vector<uint64_t> rns_moduli;
};

class GpuFheBackend {
public:
    static GpuFheBackend& getInstance();

    GpuFheBackend(const GpuFheBackend&) = delete;
    GpuFheBackend& operator=(const GpuFheBackend&) = delete;

    void initialize(const GpuBfvParams& params);
    void generateKeys();
    bool isInitialized() const { return initialized_; }

    size_t slotCount() const;
    size_t polyModulusDegree() const;
    const GpuBfvParams& params() const;

    // RNS channel count (>= 1)
    size_t channelCount() const;

    // Per-channel plain modulus
    uint64_t plainModulus() const;            // channel 0
    uint64_t plainModulus(size_t ch) const;

    // Direct access to HEonGPU objects -- channel 0 (backward compat)
    heongpu::HEContext<heongpu::Scheme::BFV>&            context();
    heongpu::HEEncoder<heongpu::Scheme::BFV>&            encoder();
    heongpu::HEEncryptor<heongpu::Scheme::BFV>&          encryptor();
    heongpu::HEDecryptor<heongpu::Scheme::BFV>&          decryptor();
    heongpu::HEArithmeticOperator<heongpu::Scheme::BFV>& arithOp();
    heongpu::HELogicOperator<heongpu::Scheme::BFV>&      logicOp();
    heongpu::Relinkey<heongpu::Scheme::BFV>&             relinKey();
    heongpu::Galoiskey<heongpu::Scheme::BFV>&            galoisKey();

    // Per-channel access to HEonGPU objects
    heongpu::HEContext<heongpu::Scheme::BFV>&            context(size_t ch);
    heongpu::HEEncoder<heongpu::Scheme::BFV>&            encoder(size_t ch);
    heongpu::HEEncryptor<heongpu::Scheme::BFV>&          encryptor(size_t ch);
    heongpu::HEDecryptor<heongpu::Scheme::BFV>&          decryptor(size_t ch);
    heongpu::HEArithmeticOperator<heongpu::Scheme::BFV>& arithOp(size_t ch);
    heongpu::HELogicOperator<heongpu::Scheme::BFV>&      logicOp(size_t ch);
    heongpu::Relinkey<heongpu::Scheme::BFV>&             relinKey(size_t ch);
    heongpu::Galoiskey<heongpu::Scheme::BFV>&            galoisKey(size_t ch);

    void reset();

    struct Impl;
    Impl* impl() { return impl_.get(); }

private:
    GpuFheBackend();
    ~GpuFheBackend();

    std::unique_ptr<Impl> impl_;
    bool initialized_ = false;
};

} // namespace vaultdb

#endif // GPU_FHE_BACKEND_CUH_
