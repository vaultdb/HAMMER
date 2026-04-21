#ifndef FHE_FIELD_H_
#define FHE_FIELD_H_

#include "field.h"
#include "field_type.h"
#include "fhe_type_abstraction.h"
#include "openfhe.h"
#include <util/system_configuration.h>
#include <util/crypto_manager/fhe_manager.h>

#include <vector>
#include <string>
#include <variant>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <memory>


namespace vaultdb {

// Renamed FHE-specific type descriptors to avoid conflict with vaultdb::FieldType enum
    enum class FheDataType {
        INVALID,
        UNINITIALIZED,
        BOOLEAN,
        INTEGER, // Typically int32_t or similar
        LONG,    // Typically int64_t
        FLOAT,
        DOUBLE,
        // Potentially others like STRING, DATE if FheField needs to know original form
    };

    enum class FheEncodingType {
        INVALID_ENCODING,
        UNINITIALIZED_ENCODING,
        PLAINTEXT_NOENCODING,       // Unencrypted data
        BFV_PACKED_ENCODING,        // BFV scheme with batching
        BGV_PACKED_ENCODING,        // BGV scheme with batching
        CKKS_PACKED_ENCODING,       // CKKS scheme with packing
        TFHE_BOOLEAN_ENCODING,      // TFHE/FHEW for boolean circuits
        // Future extensions for hybrid/mixed encodings
        MIXED_ENCODING              // Mixed-type column (multiple schemes)
    };

    class FheTypeDescriptor {
    public:
        FheDataType dataType_ = FheDataType::INVALID;
        FheEncodingType encodingType_ = FheEncodingType::INVALID_ENCODING;
        bool isStruct_ = false;
        bool isUnion_ = false;

        FheTypeDescriptor(FheDataType dt, FheEncodingType et, bool is_struct = false, bool is_union = false)
                : dataType_(dt), encodingType_(et), isStruct_(is_struct), isUnion_(is_union) {}

        FheTypeDescriptor(FheDataType dt) // Simplified constructor if encoding is implicit or not FHE
                : dataType_(dt), encodingType_(FheEncodingType::PLAINTEXT_NOENCODING), isStruct_(false), isUnion_(false) {}

        // Default constructor for an invalid/uninitialized type
        FheTypeDescriptor() : dataType_(FheDataType::INVALID), encodingType_(FheEncodingType::INVALID_ENCODING), isStruct_(false), isUnion_(false) {}


        // Equality operator, useful for comparisons
        bool operator==(const FheTypeDescriptor& other) const {
            return dataType_ == other.dataType_ &&
                   encodingType_ == other.encodingType_ &&
                   isStruct_ == other.isStruct_ &&
                   isUnion_ == other.isUnion_;
        }

        bool operator!=(const FheTypeDescriptor& other) const {
            return !(*this == other);
        }

        // Add getters if needed, e.g.:
        // DataType getDataType() const { return dataType_; }
        // EncodingType getEncodingType() const { return encodingType_; }
    };

// Forward declare FheBaseTest to access its static members if needed by static methods
// This creates a circular dependency risk if FheBaseTest also includes FheField.h directly.
// A better approach is for FheManager to be a singleton or globally accessible service if tests need it.
// For now, we assume FheField methods requiring context/keys will receive them as parameters
// or be member functions operating on an already configured FheField instance.

// Forward declaration from fhe_base_test.h to avoid direct include here if possible
// class FheBaseTest; // Problematic due to potential circular includes

    enum class OriginalDataType {
        UNINITIALIZED,
        INTEGER,
        DOUBLE,
        BOOLEAN
    };

    struct QuantizationParams {
        uint32_t targetPrecisionBits = 0;
        uint32_t B_g = 0;
        double scale = 1.0;
        uint64_t ckksLevel = 0;
        usint simdSlots = 0;
    };

    class FheField {
    private:
        // Polymorphic FHE value storing the encrypted data
        std::unique_ptr<FheTypeBase> fhe_value_;
        
        // Field type metadata
        FieldType type_;
        FheTypeDescriptor type_desc_;
        
        // Crypto context and keys (needed for encryption/decryption operations)
        // These are stored as pointers to avoid copying heavy cryptographic objects
        lbcrypto::CryptoContext<lbcrypto::DCRTPoly> m_cryptoContext;
        lbcrypto::PublicKey<lbcrypto::DCRTPoly> m_publicKey;
        
        // Additional metadata for compatibility with existing implementation
        OriginalDataType m_originalUnderlyingType;
        bool m_isScalarReplicated;
        size_t m_numLimbs;
        size_t m_packedPlaintextCount;
        QuantizationParams m_quantParams;
        
        // Legacy support: ciphertext vector (for multi-limb or when using old API)
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> m_ciphertexts;
        
        // Helper methods
        usint getTargetSlots(const QuantizationParams& q_params) const;
        std::vector<std::vector<double>> internalQuantizeAndSplit(
            const std::vector<double>& native_values,
            const QuantizationParams& q_params);
        std::string originalUnderlyingTypeToString() const;
        static FieldType toBaseFieldType(const FheTypeDescriptor& descriptor);

    public:
        // --- Constructors ---
        FheField();
        
        FheField(std::unique_ptr<FheTypeBase> fhe_value, 
                 FieldType field_type,
                 const FheTypeDescriptor& fhe_descriptor);
        
        // Constructor with crypto context (for encryption operations)
        FheField(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc,
                 lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk,
                 const FheTypeDescriptor& fhe_descriptor);
                 
        // Factory constructors for different schemes
        static FheField createBFV(const QuantizationParams& q_params, 
                                 const FheTypeDescriptor& type_desc);
        static FheField createBGV(const QuantizationParams& q_params, 
                                 const FheTypeDescriptor& type_desc);
        static FheField createCKKS(const QuantizationParams& q_params, 
                                  const FheTypeDescriptor& type_desc);
        static FheField createTFHE(const QuantizationParams& q_params, 
                                  const FheTypeDescriptor& type_desc);

        // --- Encryption Methods ---
        template<typename T>
        static FheField createEncrypted(const T& value,
                                       const FheTypeDescriptor& fhe_descriptor,
                                       lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc,
                                       lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk,
                                       const QuantizationParams& q_params);
        
        template<typename T>
        static FheField createEncryptedVector(const std::vector<T>& values,
                                             const FheTypeDescriptor& fhe_descriptor,
                                             lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc,
                                             lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk,
                                             const QuantizationParams& q_params);

        // --- Member Encryption Methods ---
        void encryptIntVector(const std::vector<int64_t>& values, const QuantizationParams& q_params);
        void encryptDoubleVector(const std::vector<double>& values, const QuantizationParams& q_params);
        void encryptBoolVector(const std::vector<bool>& values, const QuantizationParams& q_params);
        void encryptInt(int64_t value, const QuantizationParams& q_params);
        void encryptDouble(double value, const QuantizationParams& q_params);
        void encryptBool(bool value, const QuantizationParams& q_params);

        // --- Decryption Methods ---
        template<typename T>
        T decrypt(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
        
        template<typename T>
        std::vector<T> decryptVector(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;

        // --- Accessors ---
        FieldType getType() const { return type_; }
        std::string toString() const;
        FheTypeDescriptor getFheTypeDescriptor() const { return type_desc_; }
        size_t getPackedCount() const { return fhe_value_ ? fhe_value_->getPackedCount() : 0; }
        QuantizationParams getQuantizationParams() const { return fhe_value_ ? fhe_value_->getQuantizationParams() : QuantizationParams{}; }
        
        // --- FHE Arithmetic Operations ---
        FheField add(const FheField& other) const;
        FheField multiply(const FheField& other) const;
        FheField rotate(int32_t steps) const;
        
        // --- Arithmetic Operator Overloads ---
        FheField operator+(const FheField& rhs) const;
        FheField operator-(const FheField& rhs) const;
        FheField operator*(const FheField& rhs) const;
        
        // --- Comparison Operators (return encrypted results) ---
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator==(const FheField& rhs) const;
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator!=(const FheField& rhs) const;
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator<(const FheField& rhs) const;
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator>(const FheField& rhs) const;
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator<=(const FheField& rhs) const;
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator>=(const FheField& rhs) const;
        
        // --- Boolean Logical Operators (for encrypted booleans) ---
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator&&(const FheField& rhs) const;
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator||(const FheField& rhs) const;
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator^(const FheField& rhs) const;  // XOR
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> operator!() const;  // NOT
        
        // Deprecated/alternate comparison methods
        FheField compareEqual(const FheField& other) const;
        FheField compareNot(const FheField& other) const;
        
        // --- Internal Access ---
        FheTypeBase* getFheValue() const { return fhe_value_.get(); }
        void setFheValue(std::unique_ptr<FheTypeBase> value) { fhe_value_ = std::move(value); }
        lbcrypto::CryptoContext<lbcrypto::DCRTPoly> getCryptoContext() const { return m_cryptoContext; }
        lbcrypto::PublicKey<lbcrypto::DCRTPoly> getPublicKey() const { return m_publicKey; }
    };

} // namespace vaultdb

#endif // FHE_FIELD_H_