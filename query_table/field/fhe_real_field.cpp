#include "fhe_real_field.h"

namespace vaultdb {
    FheRealField::FheRealField(const Ciphertext<DCRTPoly> &val)
            : FheField(FieldType::SECURE_FLOAT, val) {}

    FheRealField::FheRealField(const FieldType &field_type, const Ciphertext<DCRTPoly> &val)
            : FheField(FieldType::SECURE_INT, val) {}

    FheRealField::FheRealField(const std::vector<LWECiphertext> &lwe_val)
            : FheRealField(FieldType::SECURE_INT, lwe_val) {}

    FheRealField::FheRealField(const FieldType &field_type, const std::vector<LWECiphertext> &lwe_val){
        type_ = field_type;
        lwe_val_ = lwe_val;
        FheManager* manager = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_);
        fractionalBits_ = manager->fractionalBits_;
        bitWidth_ = manager->bitWidth_;
    }

    FheRealField& FheRealField::operator=(const FheRealField &other) {
        if (this != &other) {
            assert(this->type_ == other.type_);
            this->val_ = other.val_;
            this->lwe_val_ = other.lwe_val_;
        }
        return *this;
    }

    std::vector<LWECiphertext> FheRealField::operator+(const FheRealField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        return AddFixedPointBitVec(this->lwe_val_, rhs.lwe_val_, ccLWE);
    }

    std::vector<LWECiphertext> FheRealField::operator-(const FheRealField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        return SubFixedPointBitVec(this->lwe_val_, rhs.lwe_val_, ccLWE);
    }

    std::vector<LWECiphertext> FheRealField::operator*(const FheRealField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        // Determine the sign of the result
        LWECiphertext resultSign = ccLWE.EvalBinGate(BINGATE::XOR, this->lwe_val_[bitWidth_ - 1], rhs.lwe_val_[bitWidth_ - 1]);

        // Take absolute values
        std::vector<LWECiphertext> abs1 = TakeAbsolute(this->lwe_val_, ccLWE);
        std::vector<LWECiphertext> abs2 = TakeAbsolute(rhs.lwe_val_, ccLWE);

        std::vector<LWECiphertext> result(bitWidth_, ccLWE.EvalConstant(false));
        std::vector<LWECiphertext> temp(bitWidth_ * 2, ccLWE.EvalConstant(false));

        // Perform full multiplication
        for (int i = 0; i < bitWidth_; ++i) {
            for (int j = 0; j < bitWidth_; ++j) {
                LWECiphertext product = ccLWE.EvalBinGate(BINGATE::AND, abs1[i], abs2[j]);
                LWECiphertext current = temp[i + j];
                temp[i + j] = ccLWE.EvalBinGate(BINGATE::XOR, current, product);
            }
        }

        // Adjust for fixed-point representation
        for (int i = 0; i < bitWidth_; ++i) {
            if (i + 2 * fractionalBits_ < bitWidth_ * 2) {
                result[i] = temp[i + 2 * fractionalBits_];
            } else {
                result[i] = ccLWE.EvalConstant(false);
            }
        }

        // Apply the sign to the result
        return ApplySign(result, resultSign, ccLWE);
    }

    std::vector<LWECiphertext> FheRealField::operator/(const FheRealField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        // Determine the sign of the result
        LWECiphertext resultSign = ccLWE.EvalBinGate(BINGATE::XOR, this->lwe_val_[bitWidth_ - 1], rhs.lwe_val_[bitWidth_ - 1]);

        // Take absolute values
        std::vector<LWECiphertext> dividend = TakeAbsolute(this->lwe_val_, ccLWE);
        std::vector<LWECiphertext> divisor = TakeAbsolute(rhs.lwe_val_, ccLWE);

        // Shift dividend left by fractionalBits_
        std::vector<LWECiphertext> shiftedDividend(bitWidth_ * 2, ccLWE.EvalConstant(false));
        for (int i = 0; i < bitWidth_; ++i) {
            shiftedDividend[i + fractionalBits_] = dividend[i];
        }

        std::vector<LWECiphertext> quotient(bitWidth_, ccLWE.EvalConstant(false));
        std::vector<LWECiphertext> remainder = shiftedDividend;
        std::vector<LWECiphertext> extendedDivisor(bitWidth_ * 2, ccLWE.EvalConstant(false));

        // Extend divisor to match the size of shiftedDividend
        for (int i = 0; i < bitWidth_; ++i) {
            extendedDivisor[i] = divisor[i];
        }

        for (int i = bitWidth_ * 2 - 1; i >= 0; --i) {
            std::vector<LWECiphertext> subResult = SubFixedPointBitVec(
                    std::vector<LWECiphertext>(remainder.begin() + i, remainder.end()),
                    extendedDivisor,
                    ccLWE
            );

            LWECiphertext borrow = subResult.back();

            for (int j = 0; j < bitWidth_ * 2 - i; ++j) {
                LWECiphertext keep_old = ccLWE.EvalBinGate(BINGATE::AND, remainder[i+j], borrow);
                LWECiphertext use_new = ccLWE.EvalBinGate(BINGATE::AND, subResult[j], ccLWE.EvalNOT(borrow));
                remainder[i+j] = ccLWE.EvalBinGate(BINGATE::XOR, keep_old, use_new);
            }

            quotient[i % bitWidth_] = ccLWE.EvalNOT(borrow);
        }

        // Apply the sign to the result
        return ApplySign(quotient, resultSign, ccLWE);
    }

    std::vector<LWECiphertext> FheRealField::TakeAbsolute(const std::vector<LWECiphertext>& value, const BinFHEContext& ccLWE) const {
        std::vector<LWECiphertext> result(value.size());
        LWECiphertext carry = ccLWE.EvalConstant(false);
        LWECiphertext signBit = value.back();  // Store the sign bit

        // First, flip all bits
        for (size_t i = 0; i < value.size(); ++i) {
            result[i] = ccLWE.EvalNOT(value[i]);
        }

        // Then add 1 (two's complement)
        for (size_t i = 0; i < value.size(); ++i) {
            LWECiphertext sum = ccLWE.EvalBinGate(BINGATE::XOR, result[i], carry);
            carry = ccLWE.EvalBinGate(BINGATE::AND, result[i], carry);
            result[i] = sum;
        }

        // Now, we need to choose between the original value and the negated value based on the sign bit
        for (size_t i = 0; i < value.size(); ++i) {
            LWECiphertext chooseNegated = ccLWE.EvalBinGate(BINGATE::AND, result[i], signBit);
            LWECiphertext chooseOriginal = ccLWE.EvalBinGate(BINGATE::AND, value[i], ccLWE.EvalNOT(signBit));
            result[i] = ccLWE.EvalBinGate(BINGATE::XOR, chooseNegated, chooseOriginal);
        }

        return result;
    }

    std::vector<LWECiphertext> FheRealField::ApplySign(const std::vector<LWECiphertext>& value, const LWECiphertext& sign, const BinFHEContext& ccLWE) const {
        std::vector<LWECiphertext> result(value.size());
        LWECiphertext carry = sign;
        for (size_t i = 0; i < value.size(); ++i) {
            LWECiphertext flipped = ccLWE.EvalBinGate(BINGATE::XOR, value[i], sign);
            result[i] = ccLWE.EvalBinGate(BINGATE::XOR, flipped, carry);
            carry = ccLWE.EvalBinGate(BINGATE::AND, flipped, carry);
        }
        return result;
    }

    LWECiphertext FheRealField::operator==(const FheRealField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        LWECiphertext geq = *this >= rhs;
        LWECiphertext leq = rhs >= *this;
        return ccLWE.EvalBinGate(BINGATE::AND, geq, leq);
    }

    LWECiphertext FheRealField::operator!=(const FheRealField &rhs) const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalNOT(*this == rhs);
    }

    LWECiphertext FheRealField::operator>(const FheRealField &rhs) const {
        return rhs < *this;
    }

    LWECiphertext FheRealField::operator<(const FheRealField &rhs) const {
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();
        return ccLWE.EvalNOT(*this >= rhs);
    }

    LWECiphertext FheRealField::operator>=(const FheRealField &rhs) const {
        assert(this->type_ == rhs.type_);
        auto ccLWE = static_cast<FheManager*>(SystemConfiguration::getInstance().crypto_manager_)->getBoolCryptoContext();

        // Compute lhs - rhs
        std::vector<LWECiphertext> diff = SubFixedPointBitVec(this->lwe_val_, rhs.lwe_val_, ccLWE);

        // Check the sign bit (MSB)
        LWECiphertext sign_bit = diff.back();

        // Return NOT(sign_bit)
        return ccLWE.EvalNOT(sign_bit);
    }

    LWECiphertext FheRealField::operator<=(const FheRealField &rhs) const {
        return rhs >= *this;
    }
} // namespace vaultdb
