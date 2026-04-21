    #include "fhe_string_field.h"

    namespace vaultdb {
        FheStringField::FheStringField(const Ciphertext<DCRTPoly> &val)
                : FheStringField(FieldType::SECURE_STRING, val) {}

        FheStringField::FheStringField(const FieldType &field_type, const Ciphertext<DCRTPoly> &val)
                : FheField(FieldType::SECURE_STRING, val) {}

        FheStringField::FheStringField(const std::vector<LWECiphertext> &lwe_val)
                : FheStringField(FieldType::SECURE_STRING, lwe_val) {}

        FheStringField::FheStringField(const FieldType &field_type, const std::vector<LWECiphertext> &lwe_val){
            type_ = field_type;
            lwe_val_ = lwe_val;
            bitWidth_ = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->bitWidth_;
        }

        FheStringField& FheStringField::operator=(const FheStringField &other) {
            if (this != &other) {
                assert(this->type_ == other.type_);
                this->val_ = other.val_;
                this->lwe_val_ = other.lwe_val_;
            }
            return *this;
        }

        LWECiphertext FheStringField::operator==(const FheStringField &rhs) const {
            assert(this->type_ == rhs.type_);
            auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
            LWECiphertext geq = *this >= rhs;
            LWECiphertext leq = rhs >= *this;
            return ccLWE.EvalBinGate(BINGATE::AND, geq, leq);
        }

        LWECiphertext FheStringField::operator!=(const FheStringField &rhs) const {
            auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
            return ccLWE.EvalNOT(*this == rhs);
        }

        LWECiphertext FheStringField::operator>(const FheStringField &rhs) const {
            return rhs < *this;
        }

        LWECiphertext FheStringField::operator<(const FheStringField &rhs) const {
            auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
            return ccLWE.EvalNOT(*this >= rhs);
        }

        LWECiphertext FheStringField::operator>=(const FheStringField &rhs) const {
            assert(this->type_ == rhs.type_);
            auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

            // Compute lhs - rhs
            std::vector<LWECiphertext> diff = SubBitVec(this->lwe_val_, rhs.lwe_val_, ccLWE);

            // Check the sign bit (MSB)
            LWECiphertext sign_bit = diff.back();

            // Return NOT(sign_bit)
            return ccLWE.EvalNOT(sign_bit);
        }

        LWECiphertext FheStringField::operator<=(const FheStringField &rhs) const {
            return rhs >= *this;
        }
    } // namespace vaultdb
