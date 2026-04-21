#include <gtest/gtest.h>
#include "openfhe.h"
#include <test/fhe/fhe_base_test.h>
#include <query_table/field/fhe_table.h>

using namespace lbcrypto;
using namespace vaultdb;

class FheColumnarTest : public FheBaseTest {
protected:
    FheManager fhe_manager_;
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;

    QuantizationParams default_q_params_;
    FheTypeDescriptor default_double_type_desc_;
    FheTypeDescriptor default_bool_type_desc_;

    void SetUp() override {
        FheBaseTest::SetUp();
        cc = fhe_manager_.getRealCryptoContext();
        pk = fhe_manager_.getRealPublicKey();
        sk = fhe_manager_.getRealSecretKey();

        ASSERT_NE(nullptr, cc);
        ASSERT_NE(nullptr, pk);
        ASSERT_NE(nullptr, sk);

        default_q_params_ = {40, 0, std::pow(2.0, 40), 0, cc->GetRingDimension() / 2};
        default_double_type_desc_ = FheTypeDescriptor(FheDataType::DOUBLE, FheEncodingType::CKKS_PACKED_ENCODING);
        default_bool_type_desc_ = FheTypeDescriptor(FheDataType::BOOLEAN, FheEncodingType::CKKS_PACKED_ENCODING);
    }

    Ciphertext<DCRTPoly> createDummyCiphertext(const std::vector<double>& values) {
        if (!cc || !pk || values.empty()) return nullptr;
        auto pt = cc->MakeCKKSPackedPlaintext(values);
        return cc->Encrypt(pk, pt);
    }

    Ciphertext<DCRTPoly> createBoolCiphertext(const std::vector<bool>& bools) {
        std::vector<double> vals(bools.begin(), bools.end());
        return createDummyCiphertext(vals);
    }
};

// Test single-column chunk creation
TEST_F(FheColumnarTest, FheColumnChunkBasic) {
    std::vector<double> values = {1.0, 2.0, 3.0};
    auto ct = createDummyCiphertext(values);
    ASSERT_NE(nullptr, ct);

    FheColumnChunk chunk(ct, default_q_params_, default_double_type_desc_, values.size());
    ASSERT_EQ(chunk.packed_count, values.size());
    ASSERT_EQ(chunk.q_params.simdSlots, default_q_params_.simdSlots);
    ASSERT_EQ(chunk.type_desc.dataType_, FheDataType::DOUBLE);
}

// Test adding multiple chunks and dummy tags in column
TEST_F(FheColumnarTest, FheColumnWithChunksAndTags) {
    FheColumn col("test_col");

    std::vector<double> chunk1 = {10.0, 20.0};
    auto ct1 = createDummyCiphertext(chunk1);
    col.addChunk(FheColumnChunk(ct1, default_q_params_, default_double_type_desc_, chunk1.size()));

    std::vector<double> chunk2 = {30.0, 40.0, 50.0};
    auto ct2 = createDummyCiphertext(chunk2);
    col.addChunk(FheColumnChunk(ct2, default_q_params_, default_double_type_desc_, chunk2.size()));

    ASSERT_EQ(col.getTotalPackedValues(), 5);
    ASSERT_EQ(col.chunks.size(), 2);

    // Dummy tag tests
    col.initializeDummyTags(false);
    ASSERT_EQ(col.dummy_tags.size(), 5);
    ASSERT_FALSE(col.getDummyTag(2));
    col.setDummyTag(2, true);
    ASSERT_TRUE(col.getDummyTag(2));
    ASSERT_THROW(col.getDummyTag(5), std::out_of_range);
}

// Test table construction and enforcing column alignment
TEST_F(FheColumnarTest, FheTableWithAlignedColumns) {
    FheTable table("orders");

    std::vector<double> q_data = {100, 200};
    std::vector<double> p_data = {5.0, 15.0};

    FheColumn col_qty("quantity");
    col_qty.addChunk(FheColumnChunk(createDummyCiphertext(q_data), default_q_params_, default_double_type_desc_, q_data.size()));
    col_qty.initializeDummyTags(false);

    FheColumn col_price("price");
    col_price.addChunk(FheColumnChunk(createDummyCiphertext(p_data), default_q_params_, default_double_type_desc_, p_data.size()));
    col_price.initializeDummyTags(false);

    table.addColumn(col_qty);
    table.addColumn(col_price);

    ASSERT_EQ(table.total_rows, 2);
    ASSERT_EQ(table.columns.count("quantity"), 1);
    ASSERT_EQ(table.columns.count("price"), 1);
}

// Test rejection of inconsistent column
TEST_F(FheColumnarTest, FheTableRejectsMismatchedColumn) {
    FheTable table("fail_case");

    std::vector<double> q_data = {1.0, 2.0};
    FheColumn col_q("q");
    col_q.addChunk(FheColumnChunk(createDummyCiphertext(q_data), default_q_params_, default_double_type_desc_, q_data.size()));
    table.addColumn(col_q);

    std::vector<double> wrong_data = {10.0, 20.0, 30.0};
    FheColumn col_mismatch("wrong");
    col_mismatch.addChunk(FheColumnChunk(createDummyCiphertext(wrong_data), default_q_params_, default_double_type_desc_, wrong_data.size()));

    ASSERT_THROW(table.addColumn(col_mismatch), std::runtime_error);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
