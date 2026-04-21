#ifndef GPU_FHE_COLUMN_CHUNK_CUH_
#define GPU_FHE_COLUMN_CHUNK_CUH_

#include "gpu_fhe_backend.cuh"
#include <cstddef>
#include <vector>
#include <stdexcept>

namespace vaultdb {

// GPU-resident BFV column chunk.
// Holds one or more HEonGPU BFV ciphertexts directly (one per RNS channel).
// BFV-only -- crypto parameters live in GpuFheBackend, not duplicated here.
class GpuFheColumnChunk {
public:
    std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> rns_values_;
    std::size_t packed_count;

    GpuFheColumnChunk() : packed_count(0) {}

    GpuFheColumnChunk(heongpu::Ciphertext<heongpu::Scheme::BFV> ct, std::size_t count)
        : packed_count(count) {
        rns_values_.push_back(std::move(ct));
    }

    GpuFheColumnChunk(std::vector<heongpu::Ciphertext<heongpu::Scheme::BFV>> ciphers,
                      std::size_t count)
        : rns_values_(std::move(ciphers)), packed_count(count) {}

    std::size_t size() const { return packed_count; }

    std::size_t getRnsLevel() const {
        return rns_values_.empty() ? 1 : rns_values_.size();
    }

    bool empty() const { return rns_values_.empty(); }

    heongpu::Ciphertext<heongpu::Scheme::BFV>& getCiphertext(std::size_t channel = 0) {
        if (channel >= rns_values_.size())
            throw std::out_of_range("GpuFheColumnChunk::getCiphertext: channel out of range");
        return rns_values_[channel];
    }

    const heongpu::Ciphertext<heongpu::Scheme::BFV>& getCiphertext(std::size_t channel = 0) const {
        if (channel >= rns_values_.size())
            throw std::out_of_range("GpuFheColumnChunk::getCiphertext: channel out of range");
        return rns_values_[channel];
    }

    void setCiphertext(heongpu::Ciphertext<heongpu::Scheme::BFV> ct, std::size_t channel = 0) {
        if (channel >= rns_values_.size())
            throw std::out_of_range("GpuFheColumnChunk::setCiphertext: channel out of range");
        rns_values_[channel] = std::move(ct);
    }

    void addChannel(heongpu::Ciphertext<heongpu::Scheme::BFV> ct) {
        rns_values_.push_back(std::move(ct));
    }

    static GpuFheColumnChunk fromValues(const std::vector<int64_t>& values);

    std::vector<int64_t> decryptChannel(std::size_t channel = 0) const;
};

} // namespace vaultdb

#endif // GPU_FHE_COLUMN_CHUNK_CUH_
