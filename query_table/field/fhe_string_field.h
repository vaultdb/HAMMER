#ifndef _FHE_STRING_FIELD_H_
#define _FHE_STRING_FIELD_H_

#include "fhe_field.h"

namespace vaultdb {

    class FheStringField : public FheField {
    public:
        std::vector<LWECiphertext> lwe_val_;

        FheStringField() = default;
        FheStringField(const Ciphertext<DCRTPoly> &val);
        FheStringField(const FieldType &field_type, const Ciphertext<DCRTPoly> &val);
        FheStringField(const std::vector<LWECiphertext> &lwe_val);
        FheStringField(const FieldType &field_type, const std::vector<LWECiphertext> &lwe_val);

        FheStringField &operator=(const FheStringField &other);

        LWECiphertext operator==(const FheStringField &rhs) const;
        LWECiphertext operator!=(const FheStringField &rhs) const;
        LWECiphertext operator>(const FheStringField &rhs) const;
        LWECiphertext operator<(const FheStringField &rhs) const;
        LWECiphertext operator>=(const FheStringField &rhs) const;
        LWECiphertext operator<=(const FheStringField &rhs) const;
    };
}

#endif // _FHE_STRING_FIELD_H_
