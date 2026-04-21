#include <gtest/gtest.h>
#include "openfhe.h"
#include <query_table/field/fhe_field.h>
#include <test/fhe/fhe_base_test.h>

using namespace lbcrypto;
using namespace vaultdb;

class FheIntFieldExpressionTest : public FheBaseTest {
protected:
    FheManager fhe_manager_;
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    QuantizationParams default_q_params;
    FheTypeDescriptor default_fhe_descriptor;

    void SetUp() override {
        FheBaseTest::SetUp();

        cc = fhe_manager_.getRealCryptoContext();
        pk = fhe_manager_.getRealPublicKey();
        sk = fhe_manager_.getRealSecretKey();

        ASSERT_NE(nullptr, cc) << "CKKS CryptoContext is null. FheManager not initialized for REAL numbers?";
        ASSERT_NE(nullptr, pk) << "CKKS PublicKey is null.";
        ASSERT_NE(nullptr, sk) << "CKKS SecretKey is null.";

        default_q_params.targetPrecisionBits = 40;
        default_q_params.scale = std::pow(2.0, default_q_params.targetPrecisionBits);
        default_q_params.ckksLevel = 0;
        uint32_t ringDim = cc->GetRingDimension();
        default_q_params.simdSlots = ringDim / 2;

        default_fhe_descriptor = FheTypeDescriptor(FheDataType::INTEGER,
                                                   FheEncodingType::CKKS_PACKED_ENCODING,
                                                   false, false);
    }
};

TEST_F(FheIntFieldExpressionTest, TestAddition) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);

    FheField result_field = field1 + field2;

    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 8);
}


TEST_F(FheIntFieldExpressionTest, TestAddition2) {
    FheField field1 = FheField::createEncrypted(-1, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 + field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 2);
}

TEST_F(FheIntFieldExpressionTest, TestAddition3) {
    FheField field1 = FheField::createEncrypted(-1, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-2, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 + field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, -3);
}

TEST_F(FheIntFieldExpressionTest, TestAddition4) {
    FheField field1 = FheField::createEncrypted(0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(21, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 + field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 21);
}

TEST_F(FheIntFieldExpressionTest, TestAddition5) {
    FheField field1 = FheField::createEncrypted(0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-21, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 + field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, -21);
}

TEST_F(FheIntFieldExpressionTest, TestAddition6) {
    FheField field1 = FheField::createEncrypted(-21, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(21, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 + field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 0);
}


TEST_F(FheIntFieldExpressionTest, TestSubtraction1) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 - field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 2);
}

TEST_F(FheIntFieldExpressionTest, TestSubtraction2) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-2, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 - field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 7);
}

TEST_F(FheIntFieldExpressionTest, TestSubtraction3) {
    FheField field1 = FheField::createEncrypted(-5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 - field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, -8);
}

TEST_F(FheIntFieldExpressionTest, TestSubtraction4) {
    FheField field1 = FheField::createEncrypted(-5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-3, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 - field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, -2);
}

TEST_F(FheIntFieldExpressionTest, TestMultiplication1) {
    FheField field1 = FheField::createEncrypted(4, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 * field2;
    // TODO: Add Relinearize in FheField::operator*
    // For now, if levels are an issue, this might fail or be noisy
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 12);
}

TEST_F(FheIntFieldExpressionTest, TestMultiplication2) {
    FheField field1 = FheField::createEncrypted(-4, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 * field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, -12);
}

TEST_F(FheIntFieldExpressionTest, TestMultiplication3) {
    FheField field1 = FheField::createEncrypted(-4, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-3, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1 * field2;
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 12);
}


TEST_F(FheIntFieldExpressionTest, TestAssignment) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result_field = field1; // Testing assignment
    int decrypted_result = result_field.decrypt<int>(sk);
    ASSERT_EQ(decrypted_result, 5);
}

TEST_F(FheIntFieldExpressionTest, TestEqualTo1) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 == field2;
    Plaintext plaintext_result_eq1;
    cc->Decrypt(sk, ct_result, &plaintext_result_eq1);
    plaintext_result_eq1->SetLength(1);
    bool decrypted_bool_eq1 = plaintext_result_eq1->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_eq1); // 5 == 5 is true
}

TEST_F(FheIntFieldExpressionTest, TestEqualTo2) {
    FheField field1 = FheField::createEncrypted(4, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 == field2;
    Plaintext plaintext_result_eq2;
    cc->Decrypt(sk, ct_result, &plaintext_result_eq2);
    plaintext_result_eq2->SetLength(1);
    bool decrypted_bool_eq2 = plaintext_result_eq2->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_FALSE(decrypted_bool_eq2); // 4 == 5 is false
}

TEST_F(FheIntFieldExpressionTest, TestNotEqualTo) {
    FheField field1 = FheField::createEncrypted(4, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 != field2;
    Plaintext plaintext_result_neq;
    cc->Decrypt(sk, ct_result, &plaintext_result_neq);
    plaintext_result_neq->SetLength(1);
    bool decrypted_bool_neq = plaintext_result_neq->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_neq); // 4 != 5 is true
}

TEST_F(FheIntFieldExpressionTest, TestGreaterThan) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 > field2;
    Plaintext plaintext_result_gt;
    cc->Decrypt(sk, ct_result, &plaintext_result_gt);
    plaintext_result_gt->SetLength(1);
    bool decrypted_bool_gt = plaintext_result_gt->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_gt); // 5 > 3 is true
}

TEST_F(FheIntFieldExpressionTest, TestLessThan) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 < field2;
    Plaintext plaintext_result_lt;
    cc->Decrypt(sk, ct_result, &plaintext_result_lt);
    plaintext_result_lt->SetLength(1);
    bool decrypted_bool_lt = plaintext_result_lt->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_FALSE(decrypted_bool_lt); // 5 < 3 is false
}

TEST_F(FheIntFieldExpressionTest, TestGreaterThanOrEqualTo0) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 >= field2;
    Plaintext plaintext_result_gte0;
    cc->Decrypt(sk, ct_result, &plaintext_result_gte0);
    plaintext_result_gte0->SetLength(1);
    bool decrypted_bool_gte0 = plaintext_result_gte0->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_gte0); // 5 >= 3 is true
}

TEST_F(FheIntFieldExpressionTest, TestGreaterThanOrEqualTo1) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(4, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 >= field2;
    Plaintext plaintext_result_gte1;
    cc->Decrypt(sk, ct_result, &plaintext_result_gte1);
    plaintext_result_gte1->SetLength(1);
    bool decrypted_bool_gte1 = plaintext_result_gte1->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_gte1); // 5 >= 4 is true
}

TEST_F(FheIntFieldExpressionTest, TestGreaterThanOrEqualTo2) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 >= field2;
    Plaintext plaintext_result_gte2;
    cc->Decrypt(sk, ct_result, &plaintext_result_gte2);
    plaintext_result_gte2->SetLength(1);
    bool decrypted_bool_gte2 = plaintext_result_gte2->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_gte2); // 5 >= 5 is true
}

TEST_F(FheIntFieldExpressionTest, TestGreaterThanOrEqualTo3) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(6, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 >= field2;
    Plaintext plaintext_result_gte3;
    cc->Decrypt(sk, ct_result, &plaintext_result_gte3);
    plaintext_result_gte3->SetLength(1);
    bool decrypted_bool_gte3 = plaintext_result_gte3->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_FALSE(decrypted_bool_gte3); // 5 >= 6 is false
}

TEST_F(FheIntFieldExpressionTest, TestGreaterThanOrEqualTo4) {
    FheField field1 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(7, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 >= field2;
    Plaintext plaintext_result_gte4;
    cc->Decrypt(sk, ct_result, &plaintext_result_gte4);
    plaintext_result_gte4->SetLength(1);
    bool decrypted_bool_gte4 = plaintext_result_gte4->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_FALSE(decrypted_bool_gte4); // 5 >= 7 is false
}


TEST_F(FheIntFieldExpressionTest, TestLessThanOrEqualTo) {
    FheField field1 = FheField::createEncrypted(4, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = field1 <= field2;
    Plaintext plaintext_result_lte;
    cc->Decrypt(sk, ct_result, &plaintext_result_lte);
    plaintext_result_lte->SetLength(1);
    bool decrypted_bool_lte = plaintext_result_lte->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_TRUE(decrypted_bool_lte); // 4 <= 5 is true
}


TEST_F(FheIntFieldExpressionTest, TestMillionairesProblem) {
    FheField alice = FheField::createEncrypted(7, default_fhe_descriptor, cc, pk, default_q_params);
    FheField bob = FheField::createEncrypted(12, default_fhe_descriptor, cc, pk, default_q_params);
    Ciphertext<DCRTPoly> ct_result = alice > bob;
    Plaintext plaintext_result_mp;
    cc->Decrypt(sk, ct_result, &plaintext_result_mp);
    plaintext_result_mp->SetLength(1);
    bool decrypted_bool_mp = plaintext_result_mp->GetCKKSPackedValue()[0].real() > 0.5;
    ASSERT_FALSE(decrypted_bool_mp); // 7 > 12 is false
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}