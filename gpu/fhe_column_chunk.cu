#include "fhe_column_chunk.cuh"

namespace vaultdb {

GpuFheColumnChunk GpuFheColumnChunk::fromValues(
    const std::vector<int64_t>& values) {

    auto& backend = GpuFheBackend::getInstance();
    if (!backend.isInitialized())
        throw std::runtime_error(
            "GpuFheColumnChunk::fromValues: GpuFheBackend not initialized");

    heongpu::Plaintext<heongpu::Scheme::BFV> pt(backend.context());
    backend.encoder().encode(pt, values);

    heongpu::Ciphertext<heongpu::Scheme::BFV> ct(backend.context());
    backend.encryptor().encrypt(ct, pt);

    return GpuFheColumnChunk(std::move(ct), values.size());
}

std::vector<int64_t> GpuFheColumnChunk::decryptChannel(std::size_t channel) const {
    if (channel >= rns_values_.size())
        throw std::out_of_range(
            "GpuFheColumnChunk::decryptChannel: channel out of range");

    auto& backend = GpuFheBackend::getInstance();

    heongpu::Plaintext<heongpu::Scheme::BFV> pt(backend.context());
    heongpu::Ciphertext<heongpu::Scheme::BFV> ct_copy = rns_values_[channel];
    backend.decryptor().decrypt(pt, ct_copy);

    std::vector<int64_t> result;
    backend.encoder().decode(result, pt);
    return result;
}

} // namespace vaultdb
