#include <gtest/gtest.h>
#include "openfhe.h"
#include <query_table/field/fhe_field.h>
#include <test/fhe/fhe_base_test.h>
#include <util/crypto_manager/fhe_manager.h>
#include <cmath>
#include <vector>

using namespace lbcrypto;
using namespace vaultdb;

class FheRealFieldExpressionTest : public FheBaseTest {
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

        default_fhe_descriptor = FheTypeDescriptor(FheDataType::DOUBLE,
                                                   FheEncodingType::CKKS_PACKED_ENCODING,
                                                   false, false);
    }
};

TEST_F(FheRealFieldExpressionTest, TestAddition) {
    FheField field1 = FheField::createEncrypted(5.0f, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3.0f, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 + field2;
    float decrypted_result = result.decrypt<float>(sk);
    ASSERT_NEAR(decrypted_result, 8.0f, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestAddition2) {
    FheField field1 = FheField::createEncrypted(-1.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 + field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, 2.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestAddition3) {
    FheField field1 = FheField::createEncrypted(-1.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-2.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 + field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, -3.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestAddition4) {
    FheField field1 = FheField::createEncrypted(0.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(21.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 + field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, 21.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestAddition5) {
    FheField field1 = FheField::createEncrypted(0.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-21.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 + field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, -21.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestAddition6) {
    FheField field1 = FheField::createEncrypted(-21.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(21.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 + field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, 0.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestSubtraction1) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 - field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, 2.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestSubtraction2) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-2.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 - field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, 7.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestSubtraction3) {
    FheField field1 = FheField::createEncrypted(-5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 - field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, -8.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestSubtraction4) {
    FheField field1 = FheField::createEncrypted(-5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-3.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 - field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, -2.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestAssignment) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, 5.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestEqualTo1) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 == field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, true);
}

TEST_F(FheRealFieldExpressionTest, TestEqualTo2) {
    FheField field1 = FheField::createEncrypted(4.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 == field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, false);
}

TEST_F(FheRealFieldExpressionTest, TestNotEqualTo) {
    FheField field1 = FheField::createEncrypted(4.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 != field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, true);
}

TEST_F(FheRealFieldExpressionTest, TestGreaterThan) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 > field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, true);
}

TEST_F(FheRealFieldExpressionTest, TestLessThan) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 < field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, false);
}

TEST_F(FheRealFieldExpressionTest, TestGreaterThanOrEqualTo0) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 >= field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, true);
}

TEST_F(FheRealFieldExpressionTest, TestGreaterThanOrEqualTo1) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(4.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 >= field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, true);
}

TEST_F(FheRealFieldExpressionTest, TestGreaterThanOrEqualTo2) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 >= field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, true);
}

TEST_F(FheRealFieldExpressionTest, TestGreaterThanOrEqualTo3) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(6.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 >= field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, false);
}

TEST_F(FheRealFieldExpressionTest, TestGreaterThanOrEqualTo4) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(7.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 >= field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, false);
}

TEST_F(FheRealFieldExpressionTest, TestLessThanOrEqualTo) {
    FheField field1 = FheField::createEncrypted(4.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = field1 <= field2;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, true);
}

TEST_F(FheRealFieldExpressionTest, TestMillionairesProblem) {
    FheField alice = FheField::createEncrypted(7.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField bob = FheField::createEncrypted(12.0, default_fhe_descriptor, cc, pk, default_q_params);
    auto ct_result = alice > bob;
    Plaintext plaintext_result;
    cc->Decrypt(sk, ct_result, &plaintext_result);
    const auto& complex_decrypted = plaintext_result->GetCKKSPackedValue();
    if (complex_decrypted.empty()) FAIL() << "Decryption resulted in empty vector";
    bool comparison_outcome = complex_decrypted[0].real() > 0.5;
    ASSERT_EQ(comparison_outcome, false);
}

TEST_F(FheRealFieldExpressionTest, TestMultiplication1) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(3.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 * field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, 15.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestMultiplication2) {
    FheField field1 = FheField::createEncrypted(5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-3.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 * field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, -15.0, 1e-3);
}

TEST_F(FheRealFieldExpressionTest, TestMultiplication3) {
    FheField field1 = FheField::createEncrypted(-5.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField field2 = FheField::createEncrypted(-3.0, default_fhe_descriptor, cc, pk, default_q_params);
    FheField result = field1 * field2;
    double decrypted_result = result.decrypt<double>(sk);
    ASSERT_NEAR(decrypted_result, 15.0, 1e-3);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}