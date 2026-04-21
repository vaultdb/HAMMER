#include <gtest/gtest.h>
#include "openfhe.h"
#include <query_table/field/fhe_int_field.h>
#include <query_table/field/fhe_real_field.h>
#include <test/fhe/fhe_base_test.h>

using namespace lbcrypto;
using namespace vaultdb;

class FheStringFieldExpressionTest : public FheBaseTest {
protected:
    void SetUp() override {}
};

TEST_F(FheStringFieldExpressionTest, TestCharEquality) {
    FheField field1 = FheField::encrypt('O');
    FheField field2 = FheField::encrypt('O');

    LWECiphertext result = field1 == field2;

    // Decrypt result
    LWEPlaintext decrypted_result;
    bool_crypto_context_->Decrypt(*bool_key_pair_, result, &decrypted_result);

    ASSERT_EQ(decrypted_result, 1);
}

TEST_F(FheStringFieldExpressionTest, TestCharInequality) {
    FheField field1 = FheField::encrypt('O');
    FheField field2 = FheField::encrypt('F');

    LWECiphertext result = field1 != field2;

    // Decrypt result
    LWEPlaintext decrypted_result;
    bool_crypto_context_->Decrypt(*bool_key_pair_, result, &decrypted_result);

    ASSERT_EQ(decrypted_result, 1);
}


TEST_F(FheStringFieldExpressionTest, TestStringComparison1) {
    FheField field1 = FheField::encrypt(std::string("EGYPT"));
    FheField field2 = FheField::encrypt(std::string("ARGENTINA"));

    LWECiphertext result = field1 == field2;

    // Decrypt result
    LWEPlaintext decrypted_result;
    bool_crypto_context_->Decrypt(*bool_key_pair_, result, &decrypted_result);

    ASSERT_EQ(decrypted_result, 0);
}

TEST_F(FheStringFieldExpressionTest, TestStringComparison2) {
    FheField field1 = FheField::encrypt(std::string("EGYPT"));
    FheField field2 = FheField::encrypt(std::string("ARGENTINA"));

    LWECiphertext result = field1 != field2;

    // Decrypt result
    LWEPlaintext decrypted_result;
    bool_crypto_context_->Decrypt(*bool_key_pair_, result, &decrypted_result);

    ASSERT_EQ(decrypted_result, 1);
}

TEST_F(FheStringFieldExpressionTest, TestStringComparisonLike) {
    FheField field1 = FheField::encrypt(std::string("Hello, World!"));

    LWECiphertext result = field1.like(std::string("World"));

    // Decrypt result
    LWEPlaintext decrypted_result;
    bool_crypto_context_->Decrypt(*bool_key_pair_, result, &decrypted_result);

    ASSERT_EQ(decrypted_result, 1);
}

TEST_F(FheStringFieldExpressionTest, TestStringComparisonLike2) {
    FheField field1 = FheField::encrypt(std::string("Hello, World!"));

    LWECiphertext result = field1.like(std::string("Wordl"));

    // Decrypt result
    LWEPlaintext decrypted_result;
    bool_crypto_context_->Decrypt(*bool_key_pair_, result, &decrypted_result);

    ASSERT_EQ(decrypted_result, 0);
}



int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}