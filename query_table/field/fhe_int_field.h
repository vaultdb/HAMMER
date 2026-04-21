#ifndef _FHE_INT_FIELD_H_
#define _FHE_INT_FIELD_H_

#include "fhe_field.h"

namespace vaultdb {

    class FheIntField : public FheField {
    public:
        std::vector<LWECiphertext> lwe_val_;

        FheIntField() = default;
        FheIntField(const Ciphertext<DCRTPoly> &val);
        FheIntField(const FieldType &field_type, const Ciphertext<DCRTPoly> &val);
        FheIntField(const std::vector<LWECiphertext> &lwe_val);
        FheIntField(const FieldType &field_type, const std::vector<LWECiphertext> &lwe_val);

        FheIntField &operator=(const FheIntField &other);
        std::vector<LWECiphertext> operator+(const FheIntField &rhs) const;
        std::vector<LWECiphertext> operator-(const FheIntField &rhs) const;
        std::vector<LWECiphertext> operator*(const FheIntField &rhs) const;
        std::vector<LWECiphertext> operator/(const FheIntField &rhs) const;

        LWECiphertext operator==(const FheIntField &rhs) const;
        LWECiphertext operator!=(const FheIntField &rhs) const;
        LWECiphertext operator>(const FheIntField &rhs) const;
        LWECiphertext operator<(const FheIntField &rhs) const;
        LWECiphertext operator>=(const FheIntField &rhs) const;
        LWECiphertext operator<=(const FheIntField &rhs) const;
    };
}

#endif // _FHE_INT_FIELD_H_
