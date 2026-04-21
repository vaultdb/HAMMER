#include "fhe_field.h"
#include <sstream> // For toString
#include <iomanip> // For formatting output if needed
#include <stdexcept> // For std::invalid_argument, std::runtime_error
#include "openfhe.h" // For lbcrypto types and functions
#include <vector>
#include <string>
#include <cmath>
#include <algorithm>
#include <iostream>

#ifndef NDEBUG
#define FHE_FIELD_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            std::cerr << "Assertion failed in FheField: " << (message) \
                      << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::terminate(); \
        } \
    } while (false)
#else
#define FHE_FIELD_ASSERT(condition, message) ((void)0)
#endif

// Note: Ensure that field_type.h defines the FHE_CKKS_... enum values
// and that they are accessible here.

namespace vaultdb {

// Static helper method implementation
/* static */ vaultdb::FieldType FheField::toBaseFieldType(const FheTypeDescriptor& descriptor) {
        if (descriptor.encodingType_ == FheEncodingType::PLAINTEXT_NOENCODING) {
            switch (descriptor.dataType_) {
                case FheDataType::BOOLEAN: return vaultdb::FieldType::BOOL;
                case FheDataType::INTEGER: return vaultdb::FieldType::INT;
                case FheDataType::LONG:    return vaultdb::FieldType::LONG;
                case FheDataType::FLOAT:   return vaultdb::FieldType::FLOAT;
                case FheDataType::DOUBLE:  return vaultdb::FieldType::FLOAT; // Map DOUBLE to FLOAT for base type
                default: return vaultdb::FieldType::INVALID;
            }
        } else if (descriptor.encodingType_ == FheEncodingType::CKKS_PACKED_ENCODING) {
            switch (descriptor.dataType_) {
                case FheDataType::BOOLEAN:
                    return vaultdb::FieldType::SECURE_BOOL; // Or SECURE_FLOAT if it's 0.0/1.0
                case FheDataType::INTEGER:
                case FheDataType::LONG:
                    // Map encrypted integers/longs to SECURE_LONG or SECURE_INT based on old enum
                    return vaultdb::FieldType::SECURE_LONG;
                case FheDataType::FLOAT:
                case FheDataType::DOUBLE:
                    return vaultdb::FieldType::SECURE_FLOAT;
                default: return vaultdb::FieldType::INVALID;
            }
        }
        return vaultdb::FieldType::INVALID;
    }

    FheField::FheField(
            lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc,
            lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk,
            const FheTypeDescriptor& fhe_descriptor)
            : Field<bool>(vaultdb::FieldType::FHE), // Pass the new FHE-specific type
              m_cryptoContext(cc),
              m_publicKey(pk),
              m_fheDescriptor(fhe_descriptor),
              m_originalUnderlyingType(OriginalDataType::UNINITIALIZED),
              m_isScalarReplicated(false),
              m_numLimbs(0),
              m_packedPlaintextCount(0) {
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null in FheField constructor.");
        FHE_FIELD_ASSERT(m_publicKey != nullptr, "PublicKey cannot be null in FheField constructor.");
    }

    FheField::FheField()
            : Field<bool>(vaultdb::FieldType::INVALID), // Base with old enum type
              m_cryptoContext(nullptr),
              m_publicKey(nullptr),
              m_fheDescriptor(), // Default construct FheTypeDescriptor
              m_originalUnderlyingType(OriginalDataType::UNINITIALIZED),
              m_isScalarReplicated(false),
              m_numLimbs(0),
              m_packedPlaintextCount(0) {
        // Default constructor, creates an invalid/uninitialized FheField
    }

// --- Type and String Representation ---
    FieldType FheField::getType() const {
        return this->type_; // type_ is inherited from Field<bool>
    }

    std::string FheField::originalUnderlyingTypeToString() const {
        switch (m_originalUnderlyingType) {
            case OriginalDataType::INTEGER: return "INTEGER";
            case OriginalDataType::DOUBLE: return "DOUBLE";
            case OriginalDataType::BOOLEAN: return "BOOLEAN";
            case OriginalDataType::UNINITIALIZED:
            default: return "UNINITIALIZED";
        }
    }

    std::string FheField::toString() const {
        if (m_ciphertexts.empty()) {
            return "FheField(empty)";
        }
        // For simplicity, just indicate it has encrypted data.
        // A more detailed toString might try to decrypt (if SK available, not typical for toString)
        // or show metadata like number of limbs, levels, etc.
        return "FheField(encrypted_data, limbs=" + std::to_string(m_numLimbs) +
               ", packed_count=" + std::to_string(m_packedPlaintextCount) +
               ", type=" + originalUnderlyingTypeToString() + // Call the helper
               ", scalar_replicated=" + std::to_string(m_isScalarReplicated) + ")";
    }


    // --- Private Helper: Get Target Slots ---
    usint FheField::getTargetSlots(const QuantizationParams& q_params) const {
        if (!m_cryptoContext) {
            throw std::runtime_error("getTargetSlots: CryptoContext not initialized in FheField.");
        }
        return (q_params.simdSlots == 0) ? (m_cryptoContext->GetRingDimension() / 2) : q_params.simdSlots;
    }

// --- Private Helper: Quantization (Placeholder) ---
    std::vector<std::vector<double>> FheField::internalQuantizeAndSplit(
            const std::vector<double>& native_values,
            const QuantizationParams& q_params) {

        m_numLimbs = 1; // Default to 1 limb (no splitting) - Engorgio logic will change this
        std::vector<std::vector<double>> quantized_limbs(m_numLimbs);

        if (native_values.empty()) {
            // This case should ideally be handled before calling, or return an empty structure
            // For now, let it proceed to potentially create an empty plaintext for an empty ciphertext if that's ever intended.
        }

        quantized_limbs[0].reserve(native_values.size());
        for (double val : native_values) {
            quantized_limbs[0].push_back(val); // Basic pass-through; CKKS scaling is managed by MakeCKKSPackedPlaintext
        }
        return quantized_limbs;
    }

// --- Encryption Methods ---
    void FheField::encryptIntVector(const std::vector<int64_t>& values, const QuantizationParams& q_params) {
        if (!m_cryptoContext || !m_publicKey) throw std::runtime_error("encryptIntVector: FheField not properly initialized with CryptoContext/PublicKey.");
        if (values.empty() && !q_params.simdSlots) { // Allow encrypting empty if slots are defined (for type channel)
            // Potentially initialize to an empty ciphertext state or throw based on desired semantics
            // For now, let's assume if values are empty, it's an error unless specific params allow it.
            // This behavior might need to align with how VaultDB handles empty fields/columns.
            throw std::invalid_argument("Input vector cannot be empty for encryption without explicit slot definition.");
        }

        m_quantParams = q_params;
        m_originalUnderlyingType = OriginalDataType::INTEGER;
        m_isScalarReplicated = false;
        m_packedPlaintextCount = values.size();

        std::vector<double> double_values(values.begin(), values.end());
        std::vector<std::vector<double>> processed_plaintexts = internalQuantizeAndSplit(double_values, q_params);

        m_ciphertexts.clear();
        m_ciphertexts.reserve(m_numLimbs);

        usint target_slots = getTargetSlots(q_params);
        if (m_packedPlaintextCount > target_slots && m_numLimbs == 1 && m_packedPlaintextCount > 0) {
            throw std::runtime_error("Number of values exceeds available CKKS slots for a single limb.");
        }

        for (const auto& limb_plaintext_vector : processed_plaintexts) {
            lbcrypto::Plaintext ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(limb_plaintext_vector, 1, q_params.ckksLevel, nullptr, target_slots);
            m_ciphertexts.push_back(m_cryptoContext->Encrypt(m_publicKey, ptxt));
        }
    }

    void FheField::encryptDoubleVector(const std::vector<double>& values, const QuantizationParams& q_params) {
        if (!m_cryptoContext || !m_publicKey) throw std::runtime_error("encryptDoubleVector: FheField not properly initialized.");
        if (values.empty() && !q_params.simdSlots) {
            throw std::invalid_argument("Input vector cannot be empty for encryption without explicit slot definition.");
        }

        m_quantParams = q_params;
        m_originalUnderlyingType = OriginalDataType::DOUBLE;
        m_isScalarReplicated = false;
        m_packedPlaintextCount = values.size();

        std::vector<std::vector<double>> processed_plaintexts = internalQuantizeAndSplit(values, q_params);

        m_ciphertexts.clear();
        m_ciphertexts.reserve(m_numLimbs);
        usint target_slots = getTargetSlots(q_params);
        if (m_packedPlaintextCount > target_slots && m_numLimbs == 1 && m_packedPlaintextCount > 0) {
            throw std::runtime_error("Number of values exceeds available CKKS slots for a single limb.");
        }

        for (const auto& limb_plaintext_vector : processed_plaintexts) {
            lbcrypto::Plaintext ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(limb_plaintext_vector, 1, q_params.ckksLevel, nullptr, target_slots);
            m_ciphertexts.push_back(m_cryptoContext->Encrypt(m_publicKey, ptxt));
        }
    }

    void FheField::encryptBoolVector(const std::vector<bool>& values, const QuantizationParams& q_params) {
        if (!m_cryptoContext || !m_publicKey) throw std::runtime_error("encryptBoolVector: FheField not properly initialized.");
        if (values.empty() && !q_params.simdSlots) {
            throw std::invalid_argument("Input vector cannot be empty for encryption without explicit slot definition.");
        }

        m_quantParams = q_params;
        m_originalUnderlyingType = OriginalDataType::BOOLEAN;
        m_isScalarReplicated = false;
        m_packedPlaintextCount = values.size();

        std::vector<double> double_values;
        double_values.reserve(values.size());
        for(bool b : values) {
            double_values.push_back(b ? 1.0 : 0.0);
        }

        std::vector<std::vector<double>> processed_plaintexts = internalQuantizeAndSplit(double_values, q_params);

        m_ciphertexts.clear();
        m_ciphertexts.reserve(m_numLimbs);
        usint target_slots = getTargetSlots(q_params);
        if (m_packedPlaintextCount > target_slots && m_numLimbs == 1 && m_packedPlaintextCount > 0) {
            throw std::runtime_error("Number of values exceeds available CKKS slots for a single limb.");
        }

        for (const auto& limb_plaintext_vector : processed_plaintexts) {
            lbcrypto::Plaintext ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(limb_plaintext_vector, 1, q_params.ckksLevel, nullptr, target_slots);
            m_ciphertexts.push_back(m_cryptoContext->Encrypt(m_publicKey, ptxt));
        }
    }

    void FheField::encryptInt(int64_t value, const QuantizationParams& q_params) {
        if (!m_cryptoContext || !m_publicKey) throw std::runtime_error("encryptInt: FheField not properly initialized.");
        m_quantParams = q_params;
        m_originalUnderlyingType = OriginalDataType::INTEGER;
        m_isScalarReplicated = true;
        m_packedPlaintextCount = 1;

        usint target_slots = getTargetSlots(q_params);
        if (target_slots == 0 && q_params.simdSlots == 0) { // Avoid division by zero if ring dimension is not set (e.g. context not fully ready)
            throw std::runtime_error("encryptInt: Target slots are zero, crypto context might not be fully configured or simdSlots not provided.");
        }
        std::vector<double> replicated_value_vector(target_slots > 0 ? target_slots : 1, static_cast<double>(value));

        std::vector<std::vector<double>> processed_plaintexts = internalQuantizeAndSplit(replicated_value_vector, q_params);

        m_ciphertexts.clear();
        m_ciphertexts.reserve(m_numLimbs);

        for (const auto& limb_plaintext_vector : processed_plaintexts) {
            lbcrypto::Plaintext ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(limb_plaintext_vector, 1, q_params.ckksLevel, nullptr, target_slots);
            m_ciphertexts.push_back(m_cryptoContext->Encrypt(m_publicKey, ptxt));
        }
    }

    void FheField::encryptDouble(double value, const QuantizationParams& q_params) {
        if (!m_cryptoContext || !m_publicKey) throw std::runtime_error("encryptDouble: FheField not properly initialized.");
        m_quantParams = q_params;
        m_originalUnderlyingType = OriginalDataType::DOUBLE;
        m_isScalarReplicated = true;
        m_packedPlaintextCount = 1;

        usint target_slots = getTargetSlots(q_params);
        if (target_slots == 0 && q_params.simdSlots == 0) {
            throw std::runtime_error("encryptDouble: Target slots are zero, crypto context might not be fully configured or simdSlots not provided.");
        }
        std::vector<double> replicated_value_vector(target_slots > 0 ? target_slots : 1, value);

        std::vector<std::vector<double>> processed_plaintexts = internalQuantizeAndSplit(replicated_value_vector, q_params);

        m_ciphertexts.clear();
        m_ciphertexts.reserve(m_numLimbs);

        for (const auto& limb_plaintext_vector : processed_plaintexts) {
            lbcrypto::Plaintext ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(limb_plaintext_vector, 1, q_params.ckksLevel, nullptr, target_slots);
            m_ciphertexts.push_back(m_cryptoContext->Encrypt(m_publicKey, ptxt));
        }
    }

    void FheField::encryptBool(bool value, const QuantizationParams& q_params) {
        if (!m_cryptoContext || !m_publicKey) throw std::runtime_error("encryptBool: FheField not properly initialized.");
        m_quantParams = q_params;
        m_originalUnderlyingType = OriginalDataType::BOOLEAN;
        m_isScalarReplicated = true;
        m_packedPlaintextCount = 1;

        usint target_slots = getTargetSlots(q_params);
        if (target_slots == 0 && q_params.simdSlots == 0) {
            throw std::runtime_error("encryptBool: Target slots are zero, crypto context might not be fully configured or simdSlots not provided.");
        }
        std::vector<double> replicated_value_vector(target_slots > 0 ? target_slots : 1, value ? 1.0 : 0.0);

        std::vector<std::vector<double>> processed_plaintexts = internalQuantizeAndSplit(replicated_value_vector, q_params);

        m_ciphertexts.clear();
        m_ciphertexts.reserve(m_numLimbs);

        for (const auto& limb_plaintext_vector : processed_plaintexts) {
            lbcrypto::Plaintext ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(limb_plaintext_vector, 1, q_params.ckksLevel, nullptr, target_slots);
            m_ciphertexts.push_back(m_cryptoContext->Encrypt(m_publicKey, ptxt));
        }
    }

// The initializeBaseFieldType method from the header is not strictly needed if the
// base FieldType is set directly in the FheField constructor's member initializer list
// by passing it to the Field<bool>(fhe_specific_type) base constructor.
// void FheField::initializeBaseFieldType(FieldType fhe_specific_type) {
// this->type_ = fhe_specific_type; // type_ is inherited from Field<bool>
// }

// --- Static Factory/Encryption Methods --- (Now use FheTypeDescriptor)
// Implementation for single value
    template<typename T>
    FheField FheField::createEncrypted(const T& value,
                                       const FheTypeDescriptor& fhe_descriptor, // Changed
                                       lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc,
                                       lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk,
                                       const QuantizationParams& q_params) {
        FHE_FIELD_ASSERT(cc != nullptr, "CryptoContext cannot be null for createEncrypted.");
        FHE_FIELD_ASSERT(pk != nullptr, "PublicKey cannot be null for createEncrypted.");

        FheField field(cc, pk, fhe_descriptor); // Uses the updated constructor
        field.m_quantParams = q_params;

        std::vector<T> values_vec = {value};

        if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, int32_t> || std::is_same_v<T, int>) {
            field.m_originalUnderlyingType = OriginalDataType::INTEGER;
            std::vector<int64_t> int_values(values_vec.begin(), values_vec.end());
            field.encryptIntVector(int_values, q_params);
        } else if constexpr (std::is_same_v<T, double> || std::is_same_v<T, float>) {
            field.m_originalUnderlyingType = OriginalDataType::DOUBLE;
            std::vector<double> double_values(values_vec.begin(), values_vec.end());
            field.encryptDoubleVector(double_values, q_params);
        } else if constexpr (std::is_same_v<T, bool>) {
            field.m_originalUnderlyingType = OriginalDataType::BOOLEAN;
            std::vector<double> double_values;
            double_values.push_back(value ? 1.0 : 0.0);
            field.encryptDoubleVector(double_values, q_params);
        } else {
            throw std::runtime_error("Unsupported data type for FheField::createEncrypted");
        }

        field.m_isScalarReplicated = true;
        // m_packedPlaintextCount is set by encryptXVector methods based on their direct input
        // and replication logic within them if they are the scalar encryptX versions.
        // For createEncrypted (scalar), the called encryptXVector will ultimately use
        // internalQuantizeAndSplit which handles replication if m_isScalarReplicated is true.
        // The final m_packedPlaintextCount in encryptDoubleVector becomes q_params.simdSlots.
        return field;
    }


// Implementation for vector of values
    template<typename T>
    FheField FheField::createEncryptedVector(const std::vector<T>& values,
                                             const FheTypeDescriptor& fhe_descriptor, // Changed
                                             lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc,
                                             lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk,
                                             const QuantizationParams& q_params) {
        FHE_FIELD_ASSERT(cc != nullptr, "CryptoContext cannot be null for createEncryptedVector.");
        FHE_FIELD_ASSERT(pk != nullptr, "PublicKey cannot be null for createEncryptedVector.");
        FHE_FIELD_ASSERT(!values.empty(), "Input vector cannot be empty for createEncryptedVector.");

        FheField field(cc, pk, fhe_descriptor); // Uses updated constructor
        field.m_quantParams = q_params;

        if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, int32_t> || std::is_same_v<T, int>) {
            field.m_originalUnderlyingType = OriginalDataType::INTEGER;
            std::vector<int64_t> int_values;
            std::transform(values.begin(), values.end(), std::back_inserter(int_values),
                           [](T val){ return static_cast<int64_t>(val); });
            field.encryptIntVector(int_values, q_params);
        } else if constexpr (std::is_same_v<T, double> || std::is_same_v<T, float>) {
            field.m_originalUnderlyingType = OriginalDataType::DOUBLE;
            std::vector<double> double_values;
            std::transform(values.begin(), values.end(), std::back_inserter(double_values),
                           [](T val){ return static_cast<double>(val); });
            field.encryptDoubleVector(double_values, q_params);
        } else if constexpr (std::is_same_v<T, bool>) {
            field.m_originalUnderlyingType = OriginalDataType::BOOLEAN;
            std::vector<double> double_values;
            std::transform(values.begin(), values.end(), std::back_inserter(double_values),
                           [](bool b_val){ return b_val ? 1.0 : 0.0; });
            field.encryptDoubleVector(double_values, q_params);
        } else {
            throw std::runtime_error("Unsupported data type for FheField::createEncryptedVector");
        }

        field.m_isScalarReplicated = false;
        // m_packedPlaintextCount is set by encryptXVector to values.size()
        return field;
    }

// --- Decryption Methods ---
    template<typename T>
    T FheField::decrypt(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const {
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for decrypt.");
        FHE_FIELD_ASSERT(sk != nullptr, "SecretKey cannot be null for decrypt.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty(), "Ciphertext vector is empty, cannot decrypt.");
        FHE_FIELD_ASSERT(m_numLimbs > 0, "Number of limbs is zero, cannot decrypt.");
        FHE_FIELD_ASSERT(m_numLimbs == 1, "Multi-limb decryption not yet implemented."); // Placeholder for multi-limb

        lbcrypto::Plaintext ptxt_result;
        m_cryptoContext->Decrypt(sk, m_ciphertexts[0], &ptxt_result);
        ptxt_result->SetLength(m_packedPlaintextCount > 0 ? m_packedPlaintextCount : 1); // Ensure length is set

        std::vector<double> decrypted_doubles = (const std::vector<double> &) ptxt_result->GetCKKSPackedValue();
        FHE_FIELD_ASSERT(!decrypted_doubles.empty(), "Decrypted double vector is empty.");

        if constexpr (std::is_same_v<T, bool>) {
            return static_cast<T>(std::round(decrypted_doubles[0]));
        } else if constexpr (std::is_integral_v<T>) {
            return static_cast<T>(std::round(decrypted_doubles[0]));
        } else if constexpr (std::is_floating_point_v<T>) {
            return static_cast<T>(decrypted_doubles[0]);
        } else {
            // This should not happen if T is one of the supported types
            throw std::runtime_error("Unsupported type for decryption (scalar).");
        }
    }

    template<typename T>
    std::vector<T> FheField::decryptVector(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const {
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for decryptVector.");
        FHE_FIELD_ASSERT(sk != nullptr, "SecretKey cannot be null for decryptVector.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty(), "Ciphertext vector is empty, cannot decryptVector.");
        FHE_FIELD_ASSERT(m_numLimbs > 0, "Number of limbs is zero, cannot decryptVector.");
        FHE_FIELD_ASSERT(m_numLimbs == 1, "Multi-limb decryption not yet implemented."); // Placeholder for multi-limb

        lbcrypto::Plaintext ptxt_result;
        m_cryptoContext->Decrypt(sk, m_ciphertexts[0], &ptxt_result);
        // The GetCKKSPackedValue automatically scales by the number of slots available for the level.
        // We need to ensure the length is correctly interpreted up to m_packedPlaintextCount.
        ptxt_result->SetLength(m_packedPlaintextCount);


        std::vector<double> decrypted_doubles = (const std::vector<double> &) ptxt_result->GetCKKSPackedValue();
        if (decrypted_doubles.empty() && m_packedPlaintextCount > 0) {
            throw std::runtime_error("Decryption resulted in empty vector but packed count > 0.");
        }


        std::vector<T> result_vector;
        result_vector.reserve(m_packedPlaintextCount);

        // Decrypted_doubles might be larger than m_packedPlaintextCount if simdSlots was larger.
        // We only care about the first m_packedPlaintextCount values.
        size_t limit = std::min(decrypted_doubles.size(), m_packedPlaintextCount);


        for (size_t i = 0; i < limit; ++i) {
            if constexpr (std::is_same_v<T, bool>) {
                result_vector.push_back(static_cast<T>(std::round(decrypted_doubles[i])));
            } else if constexpr (std::is_integral_v<T>) {
                result_vector.push_back(static_cast<T>(std::round(decrypted_doubles[i])));
            } else if constexpr (std::is_floating_point_v<T>) {
                result_vector.push_back(static_cast<T>(decrypted_doubles[i]));
            } else {
                // This should not happen with current template instantiations
                throw std::runtime_error("Unsupported type for decryption (vector).");
            }
        }
        // If decrypted_doubles was empty but m_packedPlaintextCount was non-zero (e.g. 0),
        // result_vector will be empty, which is correct.
        // If m_packedPlaintextCount was 0 (e.g. from an empty encryption), result_vector will be empty.
        return result_vector;
    }


// --- Factory Methods for Different Schemes ---
    FheField FheField::createBFV(const QuantizationParams& q_params, 
                                 const FheTypeDescriptor& type_desc) {
        auto fhe_value = FheTypeFactory::createBFV(0, q_params);
        return FheField(std::move(fhe_value), FieldType::SECURE_LONG, type_desc);
    }

    FheField FheField::createBGV(const QuantizationParams& q_params, 
                                 const FheTypeDescriptor& type_desc) {
        auto fhe_value = FheTypeFactory::createBGV(0, q_params);
        return FheField(std::move(fhe_value), FieldType::SECURE_LONG, type_desc);
    }

    FheField FheField::createCKKS(const QuantizationParams& q_params, 
                                  const FheTypeDescriptor& type_desc) {
        auto fhe_value = FheTypeFactory::createCKKS(0, q_params);
        return FheField(std::move(fhe_value), FieldType::SECURE_FLOAT, type_desc);
    }

    FheField FheField::createTFHE(const QuantizationParams& q_params, 
                                  const FheTypeDescriptor& type_desc) {
        auto fhe_value = FheTypeFactory::createTFHE(0, q_params);
        return FheField(std::move(fhe_value), FieldType::SECURE_BOOL, type_desc);
    }

// Update explicit template instantiations for FheTypeDescriptor
// CreateEncrypted
    template FheField FheField::createEncrypted<double>(const double&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);
    template FheField FheField::createEncrypted<float>(const float&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);
    template FheField FheField::createEncrypted<int64_t>(const int64_t&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);
    template FheField FheField::createEncrypted<int>(const int&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);
    template FheField FheField::createEncrypted<bool>(const bool&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);

// CreateEncryptedVector
    template FheField FheField::createEncryptedVector<double>(const std::vector<double>&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);
    template FheField FheField::createEncryptedVector<float>(const std::vector<float>&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);
    template FheField FheField::createEncryptedVector<int64_t>(const std::vector<int64_t>&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);
    template FheField FheField::createEncryptedVector<int>(const std::vector<int>&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);
    template FheField FheField::createEncryptedVector<bool>(const std::vector<bool>&, const FheTypeDescriptor&, lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::PublicKey<lbcrypto::DCRTPoly>, const QuantizationParams&);

// --- Homomorphic Operators (CKKS based) ---
    FheField FheField::operator+(const FheField& rhs) const {
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator+.");
        FHE_FIELD_ASSERT(m_numLimbs == 1 && rhs.m_numLimbs == 1, "Operator+ currently supports single limb only.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty() && !rhs.m_ciphertexts.empty(), "Ciphertexts cannot be empty for operator+.");
        FHE_FIELD_ASSERT(m_isScalarReplicated == rhs.m_isScalarReplicated, "Scalar replication status mismatch in operator+.");
        FHE_FIELD_ASSERT(m_packedPlaintextCount == rhs.m_packedPlaintextCount || m_isScalarReplicated || rhs.m_isScalarReplicated, "Packed count mismatch in operator+ for non-scalars.");

        FheField result = *this; // Copy LHS
        result.m_ciphertexts.clear();
        result.m_ciphertexts.push_back(m_cryptoContext->EvalAdd(m_ciphertexts[0], rhs.m_ciphertexts[0]));
        result.m_originalUnderlyingType = OriginalDataType::DOUBLE;
        return result;
    }

    FheField FheField::operator-(const FheField& rhs) const {
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator-.");
        FHE_FIELD_ASSERT(m_numLimbs == 1 && rhs.m_numLimbs == 1, "Operator- currently supports single limb only.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty() && !rhs.m_ciphertexts.empty(), "Ciphertexts cannot be empty for operator-.");
        FHE_FIELD_ASSERT(m_isScalarReplicated == rhs.m_isScalarReplicated, "Scalar replication status mismatch in operator-.");
        FHE_FIELD_ASSERT(m_packedPlaintextCount == rhs.m_packedPlaintextCount || m_isScalarReplicated || rhs.m_isScalarReplicated, "Packed count mismatch in operator- for non-scalars.");

        FheField result = *this;
        result.m_ciphertexts.clear();
        result.m_ciphertexts.push_back(m_cryptoContext->EvalSub(m_ciphertexts[0], rhs.m_ciphertexts[0]));
        result.m_originalUnderlyingType = OriginalDataType::DOUBLE;
        return result;
    }

    FheField FheField::operator*(const FheField& rhs) const {
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator*.");
        FHE_FIELD_ASSERT(m_numLimbs == 1 && rhs.m_numLimbs == 1, "Operator* currently supports single limb only.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty() && !rhs.m_ciphertexts.empty(), "Ciphertexts cannot be empty for operator*.");
        FHE_FIELD_ASSERT(m_isScalarReplicated == rhs.m_isScalarReplicated, "Scalar replication status mismatch in operator*.");
        FHE_FIELD_ASSERT(m_packedPlaintextCount == rhs.m_packedPlaintextCount || m_isScalarReplicated || rhs.m_isScalarReplicated, "Packed count mismatch in operator* for non-scalars.");

        FheField result = *this;
        result.m_ciphertexts.clear();
        result.m_ciphertexts.push_back(m_cryptoContext->EvalMult(m_ciphertexts[0], rhs.m_ciphertexts[0]));
        // Note: Relinearization would typically be needed here for CKKS after a multiplication.
        // result.m_ciphertexts[0] = m_cryptoContext->Relinearize(result.m_ciphertexts[0]);
        result.m_originalUnderlyingType = OriginalDataType::DOUBLE;
        return result;
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator==(const FheField& rhs) const {
        // Homomorphic equality: 1 - scale * (x-y)^2
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator==.");
        auto diff = m_cryptoContext->EvalSub(m_ciphertexts[0], rhs.m_ciphertexts[0]);
        auto diff_sq = m_cryptoContext->EvalMult(diff, diff);
        // Choose a scale factor (e.g., 10.0) for sharpness
        std::vector<double> scale_vec(1, 10.0);
        auto scale_ct = m_cryptoContext->EvalMult(diff_sq, m_cryptoContext->MakeCKKSPackedPlaintext(scale_vec));
        std::vector<double> one_vec(1, 1.0);
        auto one_ct = m_cryptoContext->MakeCKKSPackedPlaintext(one_vec);
        auto eq_ct = m_cryptoContext->EvalSub(one_ct, scale_ct);
        return eq_ct;
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator!=(const FheField& rhs) const {
        // NOT (a == b): 1.0 - (a == b)
        auto eq_ct = (*this == rhs);
        std::vector<double> one_vec(1, 1.0);
        auto one_ct = m_cryptoContext->MakeCKKSPackedPlaintext(one_vec);
        return m_cryptoContext->EvalSub(one_ct, eq_ct);
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator<(const FheField& rhs) const {
            FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator<.");
            FHE_FIELD_ASSERT(m_fheDescriptor.encodingType_ == rhs.m_fheDescriptor.encodingType_,
                             "FheFields must have same encoding type for comparison.");
            FHE_FIELD_ASSERT(m_numLimbs == 1 && rhs.m_numLimbs == 1,
                             "Comparison operators currently expect single-limb FheFields.");
            FHE_FIELD_ASSERT(m_packedPlaintextCount == rhs.m_packedPlaintextCount || m_isScalarReplicated || rhs.m_isScalarReplicated,
                             "Packed count mismatch for non-scalar comparison in operator<");

            // All types now use the single-limb comparison logic with placeholder polynomial.
            auto diff = m_cryptoContext->EvalSub(m_ciphertexts[0], rhs.m_ciphertexts[0]); // Computes this - rhs (a - b)

            // Placeholder less-than: 0.499 - k * (a-b). This needs a robust sign approximation polynomial.
            std::vector<double> scale_val = {0.1}; // Placeholder scale for (a-b)
            lbcrypto::Plaintext scale_ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(scale_val);
            auto scaled_diff = m_cryptoContext->EvalMult(diff, scale_ptxt); // k*(a-b)
            // Consider Relinearization: scaled_diff = m_cryptoContext->Relinearize(scaled_diff);

            std::vector<double> half_val = {0.499}; // Slightly less than 0.5 to help with >= and <= for equality case
            lbcrypto::Plaintext half_ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(half_val);
            auto lt_ct = m_cryptoContext->EvalSub(half_ptxt, scaled_diff); // 0.499 - k*(a-b)
            return lt_ct;
        }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator>(const FheField& rhs) const {
        // a > b <=> b < a
        return rhs < *this;
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator<=(const FheField& rhs) const {
        // !(a > b) = 1.0 - (a > b)
        auto gt_ct = *this > rhs;
        std::vector<double> one_vec(1, 1.0);
        auto one_ct = m_cryptoContext->MakeCKKSPackedPlaintext(one_vec);
        return m_cryptoContext->EvalSub(one_ct, gt_ct);
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator>=(const FheField& rhs) const {
        // !(a < b) = 1.0 - (a < b)
        auto lt_ct = *this < rhs;
        std::vector<double> one_vec(1, 1.0);
        auto one_ct = m_cryptoContext->MakeCKKSPackedPlaintext(one_vec);
        return m_cryptoContext->EvalSub(one_ct, lt_ct);
    }


    // --- Boolean Logical Operators (CKKS based) ---
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator&&(const FheField& rhs) const {
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator&&.");
        FHE_FIELD_ASSERT(m_numLimbs == 1 && rhs.m_numLimbs == 1, "Operator&& currently supports single limb only.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty() && !rhs.m_ciphertexts.empty(), "Ciphertexts cannot be empty for operator&&.");
        FHE_FIELD_ASSERT(m_originalUnderlyingType == OriginalDataType::BOOLEAN && rhs.m_originalUnderlyingType == OriginalDataType::BOOLEAN, "Operator&& expects boolean FheFields.");
        FHE_FIELD_ASSERT(m_isScalarReplicated == rhs.m_isScalarReplicated, "Scalar replication status mismatch in operator&&.");
        FHE_FIELD_ASSERT(m_packedPlaintextCount == rhs.m_packedPlaintextCount || m_isScalarReplicated || rhs.m_isScalarReplicated, "Packed count mismatch in operator&& for non-scalars.");

        // Homomorphic AND: a * b
        auto and_ct = m_cryptoContext->EvalMult(m_ciphertexts[0], rhs.m_ciphertexts[0]);
        // Consider Relinearization: and_ct = m_cryptoContext->Relinearize(and_ct);
        return and_ct;
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator||(const FheField& rhs) const {
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator||.");
        FHE_FIELD_ASSERT(m_numLimbs == 1 && rhs.m_numLimbs == 1, "Operator|| currently supports single limb only.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty() && !rhs.m_ciphertexts.empty(), "Ciphertexts cannot be empty for operator||.");
        FHE_FIELD_ASSERT(m_originalUnderlyingType == OriginalDataType::BOOLEAN && rhs.m_originalUnderlyingType == OriginalDataType::BOOLEAN, "Operator|| expects boolean FheFields.");
        FHE_FIELD_ASSERT(m_isScalarReplicated == rhs.m_isScalarReplicated, "Scalar replication status mismatch in operator||.");
        FHE_FIELD_ASSERT(m_packedPlaintextCount == rhs.m_packedPlaintextCount || m_isScalarReplicated || rhs.m_isScalarReplicated, "Packed count mismatch in operator|| for non-scalars.");

        // Homomorphic OR: a + b - a * b
        auto a_plus_b = m_cryptoContext->EvalAdd(m_ciphertexts[0], rhs.m_ciphertexts[0]);
        auto a_times_b = m_cryptoContext->EvalMult(m_ciphertexts[0], rhs.m_ciphertexts[0]);
        // Consider Relinearization: a_times_b = m_cryptoContext->Relinearize(a_times_b);
        auto or_ct = m_cryptoContext->EvalSub(a_plus_b, a_times_b);
        return or_ct;
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator^(const FheField& rhs) const { // XOR
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator^ (XOR).");
        FHE_FIELD_ASSERT(m_numLimbs == 1 && rhs.m_numLimbs == 1, "Operator^ (XOR) currently supports single limb only.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty() && !rhs.m_ciphertexts.empty(), "Ciphertexts cannot be empty for operator^ (XOR).");
        FHE_FIELD_ASSERT(m_originalUnderlyingType == OriginalDataType::BOOLEAN && rhs.m_originalUnderlyingType == OriginalDataType::BOOLEAN, "Operator^ (XOR) expects boolean FheFields.");
        FHE_FIELD_ASSERT(m_isScalarReplicated == rhs.m_isScalarReplicated, "Scalar replication status mismatch in operator^ (XOR).");
        FHE_FIELD_ASSERT(m_packedPlaintextCount == rhs.m_packedPlaintextCount || m_isScalarReplicated || rhs.m_isScalarReplicated, "Packed count mismatch in operator^ (XOR) for non-scalars.");

        // Homomorphic XOR: a + b - 2ab
        auto a_plus_b = m_cryptoContext->EvalAdd(m_ciphertexts[0], rhs.m_ciphertexts[0]);
        auto a_times_b = m_cryptoContext->EvalMult(m_ciphertexts[0], rhs.m_ciphertexts[0]);
        // Consider Relinearization: a_times_b = m_cryptoContext->Relinearize(a_times_b);

        std::vector<double> two_vec = {2.0};
        Plaintext two_ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(two_vec);
        // Ensure two_ptxt is at the same level as a_times_b or EvalMult can handle it.
        auto two_a_b = m_cryptoContext->EvalMult(a_times_b, two_ptxt);
        // Consider Relinearization: two_a_b = m_cryptoContext->Relinearize(two_a_b);

        auto xor_ct = m_cryptoContext->EvalSub(a_plus_b, two_a_b);
        return xor_ct;
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FheField::operator!() const { // NOT
        FHE_FIELD_ASSERT(m_cryptoContext != nullptr, "CryptoContext cannot be null for operator! (NOT).");
        FHE_FIELD_ASSERT(m_numLimbs == 1, "Operator! (NOT) currently supports single limb only.");
        FHE_FIELD_ASSERT(!m_ciphertexts.empty(), "Ciphertext cannot be empty for operator! (NOT).");
        FHE_FIELD_ASSERT(m_originalUnderlyingType == OriginalDataType::BOOLEAN, "Operator! (NOT) expects a boolean FheField.");

        // Homomorphic NOT: 1 - a
        std::vector<double> one_vec = {1.0};
        Plaintext one_ptxt = m_cryptoContext->MakeCKKSPackedPlaintext(one_vec);
        // Ensure one_ptxt is at the same level as m_ciphertexts[0] or EvalSub can handle it.
        auto not_ct = m_cryptoContext->EvalSub(one_ptxt, m_ciphertexts[0]);
        return not_ct;
    }

    // Explicit template instantiations for decrypt and decryptVector
    template float FheField::decrypt<float>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
    template double FheField::decrypt<double>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
    template int64_t FheField::decrypt<int64_t>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
    template int FheField::decrypt<int>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
    template bool FheField::decrypt<bool>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;

    template std::vector<float> FheField::decryptVector<float>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
    template std::vector<double> FheField::decryptVector<double>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
    template std::vector<int64_t> FheField::decryptVector<int64_t>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
    template std::vector<int> FheField::decryptVector<int>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
    template std::vector<bool> FheField::decryptVector<bool>(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk) const;
} // namespace vaultdb