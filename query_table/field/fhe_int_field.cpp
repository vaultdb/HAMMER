#include "fhe_int_field.h"

namespace vaultdb {
    FheIntField::FheIntField(const Ciphertext<DCRTPoly> &val)
            : FheIntField(FieldType::SECURE_INT, val) {}

    FheIntField::FheIntField(const FieldType &field_type, const Ciphertext<DCRTPoly> &val)
            : FheField(FieldType::SECURE_INT, val) {}

    FheIntField::FheIntField(const std::vector<LWECiphertext> &lwe_val)
            : FheIntField(FieldType::SECURE_INT, lwe_val) {}

    FheIntField::FheIntField(const FieldType &field_type, const std::vector<LWECiphertext> &lwe_val){
        type_ = field_type;
        lwe_val_ = lwe_val;
        bitWidth_ = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->bitWidth_;
    }

    FheIntField& FheIntField::operator=(const FheIntField &other) {
        if (this != &other) {
            assert(this->type_ == other.type_);
            this->val_ = other.val_;
            this->lwe_val_ = other.lwe_val_;
        }
        return *this;
    }

    std::vector<LWECiphertext> FheIntField::operator+(const FheIntField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        std::vector<LWECiphertext> result = AddBitVec(this->lwe_val_, rhs.lwe_val_, ccLWE);
        return result;
    }

    std::vector<LWECiphertext> FheIntField::operator-(const FheIntField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        std::vector<LWECiphertext> result = SubBitVec(this->lwe_val_, rhs.lwe_val_, ccLWE);
        return result;
    }

    std::vector<LWECiphertext> FheIntField::operator*(const FheIntField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        std::vector<LWECiphertext> sum(bitWidth_, ccLWE.EvalConstant(false));
        std::vector<LWECiphertext> temp(bitWidth_);

        for (int i = 0; i < bitWidth_; ++i) {
            // Calculate temp = op1 & op2[i]
            for (int k = 0; k < bitWidth_ - i; ++k) {
                temp[k] = ccLWE.EvalBinGate(BINGATE::AND, this->lwe_val_[k], rhs.lwe_val_[i]);
            }

            // Add temp to sum (shifted by i positions)
            LWECiphertext carry = ccLWE.EvalConstant(false);
            for (int j = 0; j < bitWidth_ - i; ++j) {
                LWECiphertext newSum = ccLWE.EvalBinGate(BINGATE::XOR, sum[i + j], temp[j]);
                newSum = ccLWE.EvalBinGate(BINGATE::XOR, newSum, carry);

                LWECiphertext carry1 = ccLWE.EvalBinGate(BINGATE::AND, sum[i + j], temp[j]);
                LWECiphertext carry2 = ccLWE.EvalBinGate(BINGATE::AND, sum[i + j], carry);
                LWECiphertext carry3 = ccLWE.EvalBinGate(BINGATE::AND, temp[j], carry);

                carry = ccLWE.EvalBinGate(BINGATE::OR, carry1, carry2);
                carry = ccLWE.EvalBinGate(BINGATE::OR, carry, carry3);

                sum[i + j] = newSum;
            }
        }

        return sum;
    }

    std::vector<LWECiphertext> FheIntField::operator/(const FheIntField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        std::vector<LWECiphertext> quotient(bitWidth_, ccLWE.EvalConstant(false));
        std::vector<LWECiphertext> remainder = this->lwe_val_;
        std::vector<LWECiphertext> overflow(bitWidth_, ccLWE.EvalConstant(false));

        // Initialize overflow
        for (int i = 1; i < bitWidth_; ++i) {
            overflow[i] = ccLWE.EvalBinGate(BINGATE::OR, overflow[i-1], rhs.lwe_val_[bitWidth_-i]);
        }

        for (int i = bitWidth_ - 1; i >= 0; --i) {
            // Subtract divisor from current remainder
            LWECiphertext borrow;
            std::vector<LWECiphertext> subResult = SubBitVec(
                    std::vector<LWECiphertext>(remainder.begin() + i, remainder.end()),
                    rhs.lwe_val_,
                    borrow,
                    ccLWE
            );

            // OR with overflow
            borrow = ccLWE.EvalBinGate(BINGATE::OR, borrow, overflow[i]);

            // Conditionally update remainder
            for (int j = 0; j < bitWidth_ - i; ++j) {
                LWECiphertext keep_old = ccLWE.EvalBinGate(BINGATE::AND, remainder[i+j], borrow);
                LWECiphertext use_new = ccLWE.EvalBinGate(BINGATE::AND, subResult[j], ccLWE.EvalNOT(borrow));
                remainder[i+j] = ccLWE.EvalBinGate(BINGATE::XOR, keep_old, use_new);
            }

            quotient[i] = ccLWE.EvalNOT(borrow);
        }

        return quotient;
    }

    LWECiphertext FheIntField::operator==(const FheIntField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        LWECiphertext geq = *this >= rhs;
        LWECiphertext leq = rhs >= *this;
        return ccLWE.EvalBinGate(BINGATE::AND, geq, leq);
    }

    LWECiphertext FheIntField::operator!=(const FheIntField &rhs) const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalNOT(*this == rhs);
    }

    LWECiphertext FheIntField::operator>(const FheIntField &rhs) const {
        return rhs < *this;
    }

    LWECiphertext FheIntField::operator<(const FheIntField &rhs) const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalNOT(*this >= rhs);
    }

    LWECiphertext FheIntField::operator>=(const FheIntField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        // Compute lhs - rhs
        std::vector<LWECiphertext> diff = SubBitVec(this->lwe_val_, rhs.lwe_val_, ccLWE);

        // Check the sign bit (MSB)
        LWECiphertext sign_bit = diff.back();

        // Return NOT(sign_bit)
        return ccLWE.EvalNOT(sign_bit);
    }

    LWECiphertext FheIntField::operator<=(const FheIntField &rhs) const {
        return rhs >= *this;
    }
} // namespace vaultdb
