#ifndef FHE_TYPE_ABSTRACTION_H_
#define FHE_TYPE_ABSTRACTION_H_

#include "openfhe.h"
#include <query_table/columnar/fhe_column_type.h>  // For QuantizationParams, FheTypeDescriptor
#include <memory>
#include <vector>
#include <variant>
#include <string>

namespace vaultdb {

// Forward declarations
class FheManager;

// FheSchemeType is now defined in fhe_column_type.h

// Abstract base class for FHE types
// Each scheme (Integer, Real, Boolean) will have its own implementation
class FheTypeBase {
public:
    virtual ~FheTypeBase() = default;
    
    // Get the scheme type
    virtual FheSchemeType getSchemeType() const = 0;
    
    // Get the underlying ciphertext (scheme-specific)
    virtual lbcrypto::Ciphertext<lbcrypto::DCRTPoly> getCiphertext() const = 0;
    virtual void setCiphertext(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) = 0;
    
    // Metadata accessors
    virtual size_t getPackedCount() const = 0;
    virtual void setPackedCount(size_t count) = 0;
    
    // Quantization parameters (for schemes that need it)
    virtual QuantizationParams getQuantizationParams() const = 0;
    virtual void setQuantizationParams(const QuantizationParams& params) = 0;
    
    // Cloning for polymorphic copying
    virtual std::unique_ptr<FheTypeBase> clone() const = 0;
    
    // Type checking helpers
    bool isBFV() const { return getSchemeType() == FheSchemeType::BFV; }
    bool isBGV() const { return getSchemeType() == FheSchemeType::BGV; }
    bool isCKKS() const { return getSchemeType() == FheSchemeType::CKKS; }
    bool isTFHE() const { return getSchemeType() == FheSchemeType::TFHE; }
    bool isPlaintext() const { return getSchemeType() == FheSchemeType::PLAINTEXT; }
    bool isIntegerScheme() const { return isBFV() || isBGV(); }
    bool isApproximateScheme() const { return isCKKS(); }
    bool isBooleanScheme() const { return isTFHE(); }
};

// ============================================================================
// FHE BFV TYPE
// ============================================================================
// Used for exact integer arithmetic operations with BFV scheme
class FheBFVType : public FheTypeBase {
private:
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext_;
    size_t packed_count_;
    QuantizationParams quant_params_;

public:
    FheBFVType() : packed_count_(0) {}
    
    FheBFVType(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct, size_t count, 
               const QuantizationParams& params = QuantizationParams())
        : ciphertext_(ct), packed_count_(count), quant_params_(params) {}

    // Implement base interface
    FheSchemeType getSchemeType() const override { return FheSchemeType::BFV; }
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> getCiphertext() const override { 
        return ciphertext_; 
    }
    
    void setCiphertext(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) override { 
        ciphertext_ = ct; 
    }
    
    size_t getPackedCount() const override { return packed_count_; }
    void setPackedCount(size_t count) override { packed_count_ = count; }
    
    QuantizationParams getQuantizationParams() const override { return quant_params_; }
    void setQuantizationParams(const QuantizationParams& params) override { quant_params_ = params; }
    
    std::unique_ptr<FheTypeBase> clone() const override {
        return std::make_unique<FheBFVType>(ciphertext_, packed_count_, quant_params_);
    }
    
    // Factory method
    static std::unique_ptr<FheBFVType> create(size_t packed_count = 0, 
                                              const QuantizationParams& params = QuantizationParams()) {
        return std::make_unique<FheBFVType>(lbcrypto::Ciphertext<lbcrypto::DCRTPoly>(), 
                                            packed_count, params);
    }
};

// ============================================================================
// FHE BGV TYPE
// ============================================================================
// Used for exact integer arithmetic operations with BGV scheme (alternative to BFV)
class FheBGVType : public FheTypeBase {
private:
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext_;
    size_t packed_count_;
    QuantizationParams quant_params_;

public:
    FheBGVType() : packed_count_(0) {}
    
    FheBGVType(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct, size_t count,
               const QuantizationParams& params = QuantizationParams())
        : ciphertext_(ct), packed_count_(count), quant_params_(params) {}

    // Implement base interface
    FheSchemeType getSchemeType() const override { return FheSchemeType::BGV; }
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> getCiphertext() const override { 
        return ciphertext_; 
    }
    
    void setCiphertext(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) override { 
        ciphertext_ = ct; 
    }
    
    size_t getPackedCount() const override { return packed_count_; }
    void setPackedCount(size_t count) override { packed_count_ = count; }
    
    QuantizationParams getQuantizationParams() const override { return quant_params_; }
    void setQuantizationParams(const QuantizationParams& params) override { quant_params_ = params; }
    
    std::unique_ptr<FheTypeBase> clone() const override {
        return std::make_unique<FheBGVType>(ciphertext_, packed_count_, quant_params_);
    }
    
    // Factory method
    static std::unique_ptr<FheBGVType> create(size_t packed_count = 0,
                                              const QuantizationParams& params = QuantizationParams()) {
        return std::make_unique<FheBGVType>(lbcrypto::Ciphertext<lbcrypto::DCRTPoly>(), 
                                            packed_count, params);
    }
};

// ============================================================================
// FHE CKKS TYPE
// ============================================================================
// Used for real-number arithmetic and approximate computations
// CKKS is the standard scheme for floating-point operations
class FheCKKSType : public FheTypeBase {
private:
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext_;
    size_t packed_count_;
    QuantizationParams quant_params_;

public:
    FheCKKSType() : packed_count_(0) {}
    
    FheCKKSType(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct, size_t count,
                const QuantizationParams& params = QuantizationParams())
        : ciphertext_(ct), packed_count_(count), quant_params_(params) {}

    // Implement base interface
    FheSchemeType getSchemeType() const override { return FheSchemeType::CKKS; }
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> getCiphertext() const override { 
        return ciphertext_; 
    }
    
    void setCiphertext(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) override { 
        ciphertext_ = ct; 
    }
    
    size_t getPackedCount() const override { return packed_count_; }
    void setPackedCount(size_t count) override { packed_count_ = count; }
    
    QuantizationParams getQuantizationParams() const override { return quant_params_; }
    void setQuantizationParams(const QuantizationParams& params) override { quant_params_ = params; }
    
    std::unique_ptr<FheTypeBase> clone() const override {
        return std::make_unique<FheCKKSType>(ciphertext_, packed_count_, quant_params_);
    }
    
    // Factory method
    static std::unique_ptr<FheCKKSType> create(size_t packed_count = 0,
                                               const QuantizationParams& params = QuantizationParams()) {
        return std::make_unique<FheCKKSType>(lbcrypto::Ciphertext<lbcrypto::DCRTPoly>(), 
                                             packed_count, params);
    }
};

// ============================================================================
// FHE TFHE TYPE (FHEW/TFHE)
// ============================================================================
// Used for boolean circuit evaluation with TFHE scheme
// NOTE: TFHE actually uses LWECiphertext in OpenFHE, but we use DCRTPoly interface
// for API consistency. In production, consider adding variant support or separate
// interface for LWE-based ciphertexts.
class FheTFHEType : public FheTypeBase {
private:
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext_;
    size_t packed_count_;
    QuantizationParams quant_params_;

public:
    FheTFHEType() : packed_count_(0) {}
    
    FheTFHEType(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct, size_t count,
                const QuantizationParams& params = QuantizationParams())
        : ciphertext_(ct), packed_count_(count), quant_params_(params) {}

    // Implement base interface
    FheSchemeType getSchemeType() const override { return FheSchemeType::TFHE; }
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> getCiphertext() const override { 
        return ciphertext_; 
    }
    
    void setCiphertext(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) override { 
        ciphertext_ = ct; 
    }
    
    size_t getPackedCount() const override { return packed_count_; }
    void setPackedCount(size_t count) override { packed_count_ = count; }
    
    QuantizationParams getQuantizationParams() const override { return quant_params_; }
    void setQuantizationParams(const QuantizationParams& params) override { quant_params_ = params; }
    
    std::unique_ptr<FheTypeBase> clone() const override {
        return std::make_unique<FheTFHEType>(ciphertext_, packed_count_, quant_params_);
    }
    
    // Factory method
    static std::unique_ptr<FheTFHEType> create(size_t packed_count = 0,
                                               const QuantizationParams& params = QuantizationParams()) {
        return std::make_unique<FheTFHEType>(lbcrypto::Ciphertext<lbcrypto::DCRTPoly>(), 
                                             packed_count, params);
    }
};

// ============================================================================
// FHE TYPE FACTORY
// ============================================================================
// Factory for creating appropriate FHE types based on scheme
class FheTypeFactory {
public:
    // Create specific scheme types with quantization params
    static std::unique_ptr<FheTypeBase> createBFV(size_t packed_count = 0, 
                                                  const QuantizationParams& params = QuantizationParams()) {
        return FheBFVType::create(packed_count, params);
    }
    
    static std::unique_ptr<FheTypeBase> createBGV(size_t packed_count = 0,
                                                  const QuantizationParams& params = QuantizationParams()) {
        return FheBGVType::create(packed_count, params);
    }
    
    static std::unique_ptr<FheTypeBase> createCKKS(size_t packed_count = 0,
                                                   const QuantizationParams& params = QuantizationParams()) {
        return FheCKKSType::create(packed_count, params);
    }
    
    static std::unique_ptr<FheTypeBase> createTFHE(size_t packed_count = 0,
                                                   const QuantizationParams& params = QuantizationParams()) {
        return FheTFHEType::create(packed_count, params);
    }
    
    // Backward compatibility aliases
    static std::unique_ptr<FheTypeBase> createInteger(size_t packed_count = 0,
                                                      const QuantizationParams& params = QuantizationParams()) {
        return createBFV(packed_count, params);  // Default to BFV for integers
    }
    
    static std::unique_ptr<FheTypeBase> createReal(size_t packed_count = 0,
                                                   const QuantizationParams& params = QuantizationParams()) {
        return createCKKS(packed_count, params);
    }
    
    static std::unique_ptr<FheTypeBase> createBoolean(size_t packed_count = 0,
                                                      const QuantizationParams& params = QuantizationParams()) {
        return createTFHE(packed_count, params);
    }
    
    // Create based on scheme type enum
    static std::unique_ptr<FheTypeBase> create(FheSchemeType scheme, 
                                              size_t packed_count = 0,
                                              const QuantizationParams& params = QuantizationParams()) {
        switch (scheme) {
            case FheSchemeType::BFV:
                return createBFV(packed_count, params);
            case FheSchemeType::BGV:
                return createBGV(packed_count, params);
            case FheSchemeType::CKKS:
                return createCKKS(packed_count, params);
            case FheSchemeType::TFHE:
                return createTFHE(packed_count, params);
            case FheSchemeType::PLAINTEXT:
                // For plaintext, we could return a special type or just use BFV with no encryption
                return createBFV(packed_count, params);
            default:
                throw std::invalid_argument("Unknown FHE scheme type");
        }
    }
};

} // namespace vaultdb

#endif // FHE_TYPE_ABSTRACTION_H_
