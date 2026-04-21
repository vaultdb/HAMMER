#ifndef FHE_COLUMN_TYPES_H_
#define FHE_COLUMN_TYPES_H_

#include <cstdint> // For uint32_t, uint64_t

namespace vaultdb {

    // FHE Scheme Types (shared across all FHE components)
    enum class FheSchemeType {
        BFV,       // BFV for integer arithmetic
        BGV,       // BGV for integer arithmetic (alternative to BFV)
        CKKS,      // CKKS for real-number arithmetic
        TFHE,      // TFHE/FHEW for boolean circuits
        PLAINTEXT  // Unencrypted (for mixed mode)
    };

    // Copied from former fhe_field.h / fhe_type.h
    enum class FheDataType {
        INVALID,
        UNINITIALIZED,
        BOOLEAN,
        INTEGER, // Typically int32_t or similar
        LONG,    // Typically int64_t
        FLOAT,
        DOUBLE,
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
        bool isQuantized_ = false;

        FheTypeDescriptor(FheDataType dt, FheEncodingType et, bool is_struct = false, bool is_union = false)
                : dataType_(dt), encodingType_(et), isStruct_(is_struct), isUnion_(is_union) {}

        FheTypeDescriptor(FheDataType dt)
                : dataType_(dt), encodingType_(FheEncodingType::PLAINTEXT_NOENCODING), isStruct_(false), isUnion_(false) {}

        FheTypeDescriptor() : dataType_(FheDataType::INVALID), encodingType_(FheEncodingType::INVALID_ENCODING), isStruct_(false), isUnion_(false) {}

        bool operator==(const FheTypeDescriptor& other) const {
            return dataType_ == other.dataType_ &&
                   encodingType_ == other.encodingType_ &&
                   isStruct_ == other.isStruct_ &&
                   isUnion_ == other.isUnion_;
        }

        bool operator!=(const FheTypeDescriptor& other) const {
            return !(*this == other);
        }
    };

    struct QuantizationParams {
        uint32_t targetPrecisionBits = 0;
        uint32_t B_g = 0; // From Engorgio, related to number of limbs for modular operations
        double scale = 1.0;
        uint64_t ckksLevel = 0;
        // usint is from OpenFHE, typically unsigned int.
        // Ensure openfhe.h or a specific openfhe type header is included where this struct is used with OpenFHE types.
        unsigned int simdSlots = 0; // Number of SIMD slots for packed encoding (BFV/CKKS)
    };

} // namespace vaultdb

#endif // FHE_COLUMN_TYPES_H_