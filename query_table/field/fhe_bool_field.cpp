#include "fhe_bool_field.h"

namespace vaultdb {
    FheBoolField::FheBoolField(const Ciphertext<DCRTPoly> &val)
            : FheBoolField(FieldType::SECURE_BOOL, val) {}

    FheBoolField::FheBoolField(const FieldType &field_type, const Ciphertext<DCRTPoly> &val)
            : FheField(FieldType::SECURE_BOOL, val) {}

    FheBoolField::FheBoolField(const LWECiphertext &lwe_val)
            : FheBoolField(FieldType::SECURE_BOOL, lwe_val) {}

    FheBoolField::FheBoolField(const FieldType &field_type, const LWECiphertext &lwe_val){
        type_ = field_type;
        lwe_val_ = lwe_val;
    }

    FheBoolField& FheBoolField::operator=(const FheBoolField &other) {
        if (this != &other) {
            assert(this->type_ == other.type_);
            this->val_ = other.val_;
            this->lwe_val_ = other.lwe_val_;
        }
        return *this;
    }

    LWECiphertext FheBoolField::operator==(const FheBoolField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalBinGate(BINGATE::XNOR, this->lwe_val_, rhs.lwe_val_);
    }

    LWECiphertext FheBoolField::operator!=(const FheBoolField &rhs) const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalBinGate(BINGATE::XOR, this->lwe_val_, rhs.lwe_val_);
    }

    LWECiphertext FheBoolField::operator&&(const FheBoolField &rhs) const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalBinGate(BINGATE::AND, this->lwe_val_, rhs.lwe_val_);
    }

    LWECiphertext FheBoolField::operator||(const FheBoolField &rhs) const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalBinGate(BINGATE::OR, this->lwe_val_, rhs.lwe_val_);
    }

    LWECiphertext FheBoolField::operator^(const FheBoolField &rhs) const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalBinGate(BINGATE::XOR, this->lwe_val_, rhs.lwe_val_);
    }

    LWECiphertext FheBoolField::operator!() const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalNOT(this->lwe_val_);
    }



} // namespace vaultdb
