#ifndef _FHE_REAL_FIELD_H_
#define _FHE_REAL_FIELD_H_

#include "fhe_field.h"

namespace vaultdb {

    class FheRealField : public FheField {
    public:
        std::vector<LWECiphertext> lwe_val_;

        FheRealField() = default;
        FheRealField(const Ciphertext<DCRTPoly> &val);
        FheRealField(const FieldType &field_type, const Ciphertext<DCRTPoly> &val);
        FheRealField(const std::vector<LWECiphertext> &lwe_val);
        FheRealField(const FieldType &field_type, const std::vector<LWECiphertext> &lwe_val);

        FheRealField &operator=(const FheRealField &other);
        std::vector<LWECiphertext> operator+(const FheRealField &rhs) const;
        std::vector<LWECiphertext> operator-(const FheRealField &rhs) const;
        std::vector<LWECiphertext> operator*(const FheRealField &rhs) const;
        std::vector<LWECiphertext> operator/(const FheRealField &rhs) const;

        LWECiphertext operator==(const FheRealField &rhs) const;
        LWECiphertext operator!=(const FheRealField &rhs) const;
        LWECiphertext operator>(const FheRealField &rhs) const;
        LWECiphertext operator<(const FheRealField &rhs) const;
        LWECiphertext operator>=(const FheRealField &rhs) const;
        LWECiphertext operator<=(const FheRealField &rhs) const;

        std::vector<LWECiphertext> TakeAbsolute(const std::vector<LWECiphertext>& value, const BinFHEContext& ccLWE) const;
        std::vector<LWECiphertext> ApplySign(const std::vector<LWECiphertext>& value, const LWECiphertext& sign, const BinFHEContext& ccLWE) const;
    };
}

#endif // _FHE_REAL_FIELD_H_
