#ifndef GPU_FHE_BACKEND_CUH_
#define GPU_FHE_BACKEND_CUH_

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
    uint64_t plain_modulus     = 65537;
    uint32_t mult_depth        = 15;
    std::vector<int> galois_steps;
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
    uint64_t plainModulus() const;
    const GpuBfvParams& params() const;

    // Encode / Decode
    void* encodePacked(const std::vector<uint64_t>& message);
    void* encodePackedSigned(const std::vector<int64_t>& message);
    std::vector<uint64_t> decodePacked(void* plaintext_handle);
    std::vector<int64_t> decodePackedSigned(void* plaintext_handle);

    // Encrypt / Decrypt
    void* encrypt(void* plaintext_handle);
    void* decrypt(void* ciphertext_handle);

    // Arithmetic (all return new ciphertext handle)
    void* add(void* ct1, void* ct2);
    void* addInplace(void* ct1, void* ct2);
    void* addPlain(void* ct, void* pt);
    void* sub(void* ct1, void* ct2);
    void* subInplace(void* ct1, void* ct2);
    void* subPlain(void* ct, void* pt);
    void* multiply(void* ct1, void* ct2);
    void* multiplyInplace(void* ct1, void* ct2);
    void* multiplyPlain(void* ct, void* pt);
    void* negate(void* ct);

    // Rotation
    void* rotateRows(void* ct, int shift);
    void* rotateRowsInplace(void* ct, int shift);

    // Lifetime management for opaque handles
    void destroyCiphertext(void* ct);
    void destroyPlaintext(void* pt);

    // Convenience: encrypt a vector end-to-end
    void* encryptVector(const std::vector<int64_t>& message);
    std::vector<int64_t> decryptVector(void* ciphertext_handle);

    void reset();

    // Access to the raw impl (only from .cu files)
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
