#ifndef _FHE_BOOL_FIELD_H_
#define _FHE_BOOL_FIELD_H_

#include "fhe_field.h"

namespace vaultdb {

    class FheBoolField : public FheField {
    public:
        LWECiphertext lwe_val_;

        FheBoolField() = default;
        FheBoolField(const Ciphertext<DCRTPoly> &val);
        FheBoolField(const FieldType &field_type, const Ciphertext<DCRTPoly> &val);
        FheBoolField(const LWECiphertext &lwe_val);
        FheBoolField(const FieldType &field_type, const LWECiphertext &lwe_val);

        FheBoolField &operator=(const FheBoolField &other);

        LWECiphertext operator==(const FheBoolField &rhs) const;
        LWECiphertext operator!=(const FheBoolField &rhs) const;
        LWECiphertext operator&&(const FheBoolField &rhs) const;
        LWECiphertext operator||(const FheBoolField &rhs) const;
        LWECiphertext operator^(const FheBoolField &rhs) const;
        LWECiphertext operator!() const;
    };
}

#endif // _FHE_BOOL_FIELD_H_
