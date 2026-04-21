#ifndef FHE_COLUMN_CHUNK_H_
#define FHE_COLUMN_CHUNK_H_

#include "openfhe.h"  // lbcrypto::Ciphertext, DCRTPoly
#include "fhe_column_type.h" // FheTypeDescriptor, QuantizationParams
#include <query_table/field/fhe_type_abstraction.h> // FheTypeBase
#include <query_table/columnar/column_chunk_base.h>  // ColumnChunkBase<FheTypeBase*>
#include <cstddef>   // For std::size_t
#include <memory>
#include <vector>

namespace vaultdb {

    // FheColumnChunk now inherits from ColumnChunkBase<FheTypeBase*> for proper type safety.
    // Supports RNS: when rns_values_.size() > 1, each element is one RNS channel (same logical chunk).
    class FheColumnChunk : public ColumnChunkBase<FheTypeBase*> {
    public:
        // One FheTypeBase per RNS channel (size 1 = single modulus; 2..N = multi-channel RNS)
        std::vector<std::unique_ptr<FheTypeBase>> rns_values_;
        std::size_t packed_count;  // Number of real (non-padding) values
        FheTypeDescriptor type_desc;  // Type descriptor metadata

        FheColumnChunk() : packed_count(0) {}

        FheColumnChunk(std::unique_ptr<FheTypeBase> value, std::size_t count)
                : packed_count(count) {
            if (value) rns_values_.push_back(std::move(value));
        }

        FheColumnChunk(std::unique_ptr<FheTypeBase> value, std::size_t count,
                      const FheTypeDescriptor& desc)
                : packed_count(count), type_desc(desc) {
            if (value) rns_values_.push_back(std::move(value));
        }

        // Constructor for backward compatibility (direct ciphertext, single channel)
        FheColumnChunk(lbcrypto::Ciphertext<lbcrypto::DCRTPoly> cipher,
                      const QuantizationParams& q_params,
                      const FheTypeDescriptor& desc,
                      std::size_t count)
                : packed_count(count), type_desc(desc) {
            std::unique_ptr<FheTypeBase> wrapped;
            if (desc.encodingType_ == FheEncodingType::CKKS_PACKED_ENCODING) {
                wrapped = std::make_unique<FheCKKSType>(cipher, count, q_params);
            } else if (desc.encodingType_ == FheEncodingType::BFV_PACKED_ENCODING) {
                wrapped = std::make_unique<FheBFVType>(cipher, count, q_params);
            } else if (desc.encodingType_ == FheEncodingType::BGV_PACKED_ENCODING) {
                wrapped = std::make_unique<FheBGVType>(cipher, count, q_params);
            } else {
                throw std::runtime_error("Unsupported encoding type for FheColumnChunk direct cipher constructor");
            }
            rns_values_.push_back(std::move(wrapped));
        }

        // Constructor for RNS (multiple ciphertexts, one per channel; BFV only)
        FheColumnChunk(const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ciphers,
                      const QuantizationParams& q_params,
                      const FheTypeDescriptor& desc,
                      std::size_t count)
                : packed_count(count), type_desc(desc) {
            if (desc.encodingType_ != FheEncodingType::BFV_PACKED_ENCODING) {
                throw std::runtime_error("FheColumnChunk RNS constructor supports BFV only");
            }
            for (const auto& ct : ciphers) {
                rns_values_.push_back(std::make_unique<FheBFVType>(ct, count, q_params));
            }
        }

        // Number of RNS channels (1 = single modulus, 2..N = multi-channel RNS)
        size_t getRnsLevel() const {
            return rns_values_.empty() ? 1 : rns_values_.size();
        }

        // Implement ColumnChunkBase<FheTypeBase*> interface
        std::size_t size() const override { return packed_count; }
        std::unique_ptr<FheTypeBase> getPackedValue() const override {
            if (rns_values_.empty() || !rns_values_[0]) return nullptr;
            return rns_values_[0]->clone();
        }
        void setPackedValue(std::unique_ptr<FheTypeBase> value) override {
            if (rns_values_.empty()) rns_values_.push_back(std::move(value));
            else rns_values_[0] = std::move(value);
        }

        // Convenience methods for backward compatibility
        const FheTypeBase* getFheValue() const {
            return rns_values_.empty() ? nullptr : rns_values_[0].get();
        }
        FheTypeBase* getFheValue() {
            return rns_values_.empty() ? nullptr : rns_values_[0].get();
        }
        void setFheValue(std::unique_ptr<FheTypeBase> value) {
            if (rns_values_.empty()) rns_values_.push_back(std::move(value));
            else rns_values_[0] = std::move(value);
        }

        // Backward compatibility: channel 0
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext() const {
            return getCiphertext(0);
        }
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> getCiphertext() const {
            return getCiphertext(0);
        }
        // Per-channel access for RNS (channel 0 .. getRnsLevel()-1)
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> getCiphertext(size_t channel) const {
            if (channel >= rns_values_.size() || !rns_values_[channel]) return nullptr;
            return rns_values_[channel]->getCiphertext();
        }

        QuantizationParams q_params() const {
            return rns_values_.empty() ? QuantizationParams{} : rns_values_[0]->getQuantizationParams();
        }
        
        // Factory methods for different schemes
        static FheColumnChunk createCKKS(const QuantizationParams& q_params, 
                                        const FheTypeDescriptor& type_desc,
                                        std::size_t packed_count = 0);
        static FheColumnChunk createBFV(const QuantizationParams& q_params, 
                                       const FheTypeDescriptor& type_desc,
                                       std::size_t packed_count = 0);
        static FheColumnChunk createBGV(const QuantizationParams& q_params, 
                                       const FheTypeDescriptor& type_desc,
                                       std::size_t packed_count = 0);
    };

} // namespace vaultdb
#endif // FHE_COLUMN_CHUNK_H_
