#include <gtest/gtest.h>
#include "openfhe.h"
#include <query_table/field/fhe_field.h>
#include <test/fhe/fhe_base_test.h>

using namespace lbcrypto;
using namespace vaultdb;


class FheBoolFieldExpressionTest : public FheBaseTest {
protected:
    FheManager fhe_manager_;
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    QuantizationParams default_q_params;
    FheTypeDescriptor default_fhe_descriptor;

    void SetUp() override {
        FheBaseTest::SetUp(); // Call base class setup first

        // Initialize FHE context and keys using the local fhe_manager_
        // This assumes FheBaseTest::SetUp() might initialize its own manager or a global one
        // and this derived class uses its specific manager instance.
        cc = fhe_manager_.getRealCryptoContext(); // Using REAL for underlying CKKS
        pk = fhe_manager_.getRealPublicKey();
        sk = fhe_manager_.getRealSecretKey();

        ASSERT_NE(nullptr, cc) << "CKKS CryptoContext is null. FheManager not initialized for REAL numbers?";
        ASSERT_NE(nullptr, pk) << "CKKS PublicKey is null.";
        ASSERT_NE(nullptr, sk) << "CKKS SecretKey is null.";

        // Setup default quantization parameters for boolean operations (encoded as 0.0 or 1.0)
        default_q_params.targetPrecisionBits = 40; // Sufficient for 0/1 distinction
        default_q_params.scale = std::pow(2.0, default_q_params.targetPrecisionBits);
        default_q_params.ckksLevel = 0; // Initial level for fresh encryptions
        if (cc) { // Ensure cc is not null before calling GetRingDimension
            uint32_t ringDim = cc->GetRingDimension();
            default_q_params.simdSlots = ringDim / 2;
        } else {
            default_q_params.simdSlots = 0; // Avoid segfault if cc is null, though ASSERT should catch it
        }

        // Setup default FHE type descriptor for BOOLEAN with CKKS encoding
        default_fhe_descriptor = FheTypeDescriptor(FheDataType::BOOLEAN,
                                                   FheEncodingType::CKKS_PACKED_ENCODING,
                                                   false, false);
    }
};

TEST_F(FheBoolFieldExpressionTest, TestAND) {
    FheField field1 = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(false, default_fhe_descriptor, cc, pk, default_q_params);

    Ciphertext<DCRTPoly> ct_result = field1 && field2;
    Plaintext plaintext_result_and;
    cc->Decrypt(sk, ct_result, &plaintext_result_and);
    plaintext_result_and->SetLength(1);
    bool decrypted_bool_and = plaintext_result_and->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_FALSE(decrypted_bool_and);  // true AND false = false
}

TEST_F(FheBoolFieldExpressionTest, TestOR) {
    FheField field1 = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(false, default_fhe_descriptor, cc, pk, default_q_params);

    Ciphertext<DCRTPoly> ct_result = field1 || field2;
    Plaintext plaintext_result_or;
    cc->Decrypt(sk, ct_result, &plaintext_result_or);
    plaintext_result_or->SetLength(1);
    bool decrypted_bool_or = plaintext_result_or->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_or);  // true OR false = true
}

TEST_F(FheBoolFieldExpressionTest, TestXOR) {
    FheField field1 = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);

    Ciphertext<DCRTPoly> ct_result = field1 ^ field2;
    Plaintext plaintext_result_xor;
    cc->Decrypt(sk, ct_result, &plaintext_result_xor);
    plaintext_result_xor->SetLength(1);
    bool decrypted_bool_xor = plaintext_result_xor->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_FALSE(decrypted_bool_xor);  // true XOR true = false
}

TEST_F(FheBoolFieldExpressionTest, TestNOT) {
    FheField field = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);

    Ciphertext<DCRTPoly> ct_result = !field;
    Plaintext plaintext_result_not;
    cc->Decrypt(sk, ct_result, &plaintext_result_not);
    plaintext_result_not->SetLength(1);
    bool decrypted_bool_not = plaintext_result_not->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_FALSE(decrypted_bool_not);  // NOT true = false
}

TEST_F(FheBoolFieldExpressionTest, TestEqualTo) {
    FheField field1 = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);

    Ciphertext<DCRTPoly> ct_result = field1 == field2;
    Plaintext plaintext_result_eq;
    cc->Decrypt(sk, ct_result, &plaintext_result_eq);
    plaintext_result_eq->SetLength(1);
    bool decrypted_bool_eq = plaintext_result_eq->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_eq);  // true == true is true
}

TEST_F(FheBoolFieldExpressionTest, TestNotEqualTo) {
    FheField field1 = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(false, default_fhe_descriptor, cc, pk, default_q_params);

    Ciphertext<DCRTPoly> ct_result = field1 != field2;
    Plaintext plaintext_result_neq;
    cc->Decrypt(sk, ct_result, &plaintext_result_neq);
    plaintext_result_neq->SetLength(1);
    bool decrypted_bool_neq = plaintext_result_neq->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_neq);  // true != false is true
}

TEST_F(FheBoolFieldExpressionTest, TestAssignment) {
    FheField field1 = FheField::createEncrypted(true, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = field1;

    bool decrypted_value = field2.decrypt<bool>(sk);
    ASSERT_TRUE(decrypted_value);  // Should be true
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}