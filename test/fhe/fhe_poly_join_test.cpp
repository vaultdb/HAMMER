#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <util/type_utilities.h>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>
#include <operators/columnar/fhe_sql_input.h>
#include <query_table/columnar/fhe_column_table.h>
#include <util/crypto_manager/fhe_manager.h>
#include <test/fhe/fhe_base_test.h>
#include "openfhe.h"

// Flags in util/google_test_flags.cpp, DECLAREd in util/google_test_flags.h
using namespace lbcrypto;
using namespace vaultdb;
using namespace std::chrono;

class FhePolyJoinTest : public FheBaseTest {

protected:
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    QuantizationParams default_q_params;

    void SetUp() override {
        FheBaseTest::SetUp();

        FheManager& fhe_manager = FheManager::getInstance();

        cc = fhe_manager.getRealCryptoContext();
        pk = fhe_manager.getRealPublicKey();
        sk = fhe_manager.getRealSecretKey();

        ASSERT_NE(nullptr, cc) << "CKKS CryptoContext is null. FheManager not initialized for REAL numbers?";
        ASSERT_NE(nullptr, pk) << "CKKS PublicKey is null.";
        ASSERT_NE(nullptr, sk) << "CKKS SecretKey is null.";

        default_q_params = fhe_manager.getDefaultQuantizationParams();
    }

    // Load polynomial coefficients from .txt file
    std::vector<double> loadCoefficientsFromTxt(const std::string& filename) {
        std::ifstream infile(filename);
        if (!infile.is_open()) {
            throw std::runtime_error("Could not open file: " + filename);
        }

        std::vector<double> coeffs;
        double val;
        while (infile >> val) {
            coeffs.push_back(val);
        }
        
        std::cout << "[PolyJoin] Loaded " << coeffs.size() << " coefficients from " << filename << std::endl;
        if (coeffs.size() <= 10) {
            std::cout << "[PolyJoin] Coefficients: ";
            for (double c : coeffs) std::cout << c << " ";
            std::cout << std::endl;
        } else {
            std::cout << "[PolyJoin] First 5 coefficients: ";
            for (size_t i = 0; i < 5; ++i) std::cout << coeffs[i] << " ";
            std::cout << "... (and " << coeffs.size() - 5 << " more)" << std::endl;
        }
        
        return coeffs;
    }

    int loadBetaShift(const std::string& metaFile) {
        std::ifstream in(metaFile);
        if (!in) throw std::runtime_error("Cannot open meta file: " + metaFile);
        int shift;  in >> shift;
        return shift;
    }

    // Evaluate polynomial at given points and return results
    std::vector<double> evaluatePolynomial(const std::vector<double>& coeffs, const std::vector<double>& points) {
        std::vector<double> results;
        results.reserve(points.size());
        
        for (double x : points) {
            double result = 0.0;
            double xn = 1.0;
            for (double c : coeffs) {
                result += c * xn;
                xn *= x;
            }
            results.push_back(result);
        }
        
        return results;
    }

    void printPlainTable(const vaultdb::PlainColumnTable* table, const std::string& label = "") {
        using namespace vaultdb;

        if (!table) {
            std::cout << "[PrintTable] " << label << " is null." << std::endl;
            return;
        }

        const auto& schema = table->getSchema();
        const auto column_names = table->getColumnNames();
        const size_t row_count = table->getRowCount();

        std::cout << "[PrintTable] " << label << " with " << row_count << " rows:" << std::endl;

        // Print header
        std::cout << "RowIdx\t";
        for (const auto& name : column_names) {
            std::cout << name << "\t";
        }
        std::cout << "\n";

        for (size_t r = 0; r < std::min(row_count, size_t(20)); ++r) { // Limit to first 20 rows
            std::cout << r << "\t";
            for (size_t col_idx = 0; col_idx < column_names.size(); ++col_idx) {
                const std::string& col_name = column_names[col_idx];
                auto column = std::dynamic_pointer_cast<PlainColumn>(table->getColumn(col_name));
                if (!column) {
                    std::cout << "[null]\t";
                    continue;
                }

                // Locate the field in the right chunk
                PlainField field;
                size_t remaining = r;
                bool found = false;

                for (const auto& chunk : column->getPlainChunks()) {
                    if (chunk->size() > remaining) {
                        field = chunk->getValue(remaining);
                        found = true;
                        break;
                    } else {
                        remaining -= chunk->size();
                    }
                }

                if (!found) {
                    std::cout << "[err]\t";
                    continue;
                }

                // Use actual field type instead of schema field type
                switch (field.getType()) {
                    case FieldType::INT:
                        std::cout << field.getValue<int32_t>() << "\t";
                        break;
                    case FieldType::LONG:
                        std::cout << field.getValue<int64_t>() << "\t";
                        break;
                    case FieldType::FLOAT:
                        std::cout << field.getValue<float>() << "\t";
                        break;
                    case FieldType::BOOL:
                        std::cout << (field.getValue<bool>() ? "true" : "false") << "\t";
                        break;
                    case FieldType::STRING:
                        std::cout << field.getValue<std::string>() << "\t";
                        break;
                    default:
                        std::cout << "[unsupported]\t";
                }
            }
            std::cout << "\n";
        }
        if (row_count > 20) {
            std::cout << "... (and " << row_count - 20 << " more rows)" << std::endl;
        }
    }
};

// Test FHE polynomial evaluation
TEST_F(FhePolyJoinTest, test_fhe_polynomial_evaluation) {
    std::cout << "\n=== FHE Polynomial Evaluation Test ===" << std::endl;

    int betaShift = loadBetaShift("/home/vaultdb/home/alchemy_SIGMOD/vaultdb-core/src/main/cpp/poly_join/P_orders.meta");
    std::cout << "[PolyJoin] β-shift = " << betaShift << std::endl;
    double beta   = std::ldexp(1.0, betaShift);

    try {
        // Load coefficients
        auto coefP_orders = loadCoefficientsFromTxt("/home/vaultdb/home/alchemy_SIGMOD/vaultdb-core/src/main/cpp/poly_join/P_orders.txt");
        auto coefQ_orderdate = loadCoefficientsFromTxt("/home/vaultdb/home/alchemy_SIGMOD/vaultdb-core/src/main/cpp/poly_join/Q_orders_o_orderdate.txt");
        // Create test FK values (order keys)
        std::vector<double> fk_values = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
        
        // Pad to match slot size
        size_t slot_size = cc->GetRingDimension() / 2;
        while (fk_values.size() < slot_size) {
            fk_values.push_back(0.0);
        }

        std::cout << "[PolyJoin] Creating FHE ciphertext with " << fk_values.size() << " slots" << std::endl;
        std::cout << "[PolyJoin] FK values (first 8): ";
        for (size_t i = 0; i < 8; ++i) {
            std::cout << fk_values[i] << " ";
        }
        std::cout << std::endl;

        // Encrypt FK values
        auto pt_fk = cc->MakeCKKSPackedPlaintext(fk_values);
        auto ct_fk = cc->Encrypt(pk, pt_fk);

        std::cout << "[PolyJoin] FK ciphertext level: " << ct_fk->GetLevel() << std::endl;

        // Evaluate P(x) on encrypted FK values
        auto start_time = high_resolution_clock::now();
        auto ct_P_result = cc->EvalPoly(ct_fk, coefP_orders);
//        auto ct_P_result = cc->EvalMult(ct_P_scaled, beta);

        std::cout << "[PolyJoin] ct_P_result scale=" << ct_P_result->GetScalingFactor()
                  << " level=" << ct_P_result->GetLevel() << std::endl;

//        auto end_time = high_resolution_clock::now();
//        auto duration = duration_cast<milliseconds>(end_time - start_time);
//
//        std::cout << "[PolyJoin] P(FK) evaluation completed in " << duration.count() << " ms" << std::endl;
//        std::cout << "[PolyJoin] P(FK) ciphertext level: " << ct_P_result->GetLevel() << std::endl;
//
//        // Evaluate Q(x) on encrypted FK values
//        start_time = high_resolution_clock::now();
//        auto ct_Q_scaled = cc->EvalPoly(ct_fk, coefQ_orderdate);
//        auto ct_Q_result = cc->EvalMult(ct_Q_scaled, beta);
//
//        end_time = high_resolution_clock::now();
//        duration = duration_cast<milliseconds>(end_time - start_time);
//
//        std::cout << "[PolyJoin] Q(FK) evaluation completed in " << duration.count() << " ms" << std::endl;
//        std::cout << "[PolyJoin] Q(FK) ciphertext level: " << ct_Q_result->GetLevel() << std::endl;

        // Decrypt and verify results
        Plaintext pt_P_decrypted, pt_Q_decrypted;
        cc->Decrypt(sk, ct_P_result, &pt_P_decrypted);
//        cc->Decrypt(sk, ct_Q_result, &pt_Q_decrypted);

        auto P_values = pt_P_decrypted->GetRealPackedValue();
//        auto Q_values = pt_Q_decrypted->GetRealPackedValue();

//        std::cout << "[PolyJoin] Decrypted results (first 8 slots):" << std::endl;
//        for (size_t i = 0; i < 8; ++i) {
//            std::cout << "  Slot " << i << ": P=" << P_values[i] << ", Q=" << Q_values[i] << std::endl;
//        }

        // Verify that P(x) is close to 0 for valid order keys (1-5)
        for (size_t i = 0; i < 5; ++i) {
            EXPECT_NEAR(P_values[i], 0.0, 0.1) << "P(" << fk_values[i] << ") should be close to 0";
        }

        std::cout << "[PolyJoin] FHE polynomial evaluation test passed!" << std::endl;

    } catch (const std::exception& e) {
        FAIL() << "Exception during FHE polynomial evaluation: " << e.what();
    }
}

// Test polynomial-based join simulation
//TEST_F(FhePolyJoinTest, test_polynomial_based_join_simulation) {
//    std::cout << "\n=== Polynomial-Based Join Simulation Test ===" << std::endl;
//
//    try {
//        // Load coefficients
//        auto coefP_orders = loadCoefficientsFromTxt("P_orders.txt");
//        auto coefQ_orderdate = loadCoefficientsFromTxt("Q_orders_o_orderdate.txt");
//
//        // Create test FK values (some valid, some invalid)
//        std::vector<double> fk_values = {1.0, 2.0, 3.0, 4.0, 5.0, 99.0, 100.0, 101.0};
//
//        // Pad to match slot size
//        size_t slot_size = cc->GetRingDimension() / 2;
//        while (fk_values.size() < slot_size) {
//            fk_values.push_back(0.0);
//        }
//
//        std::cout << "[PolyJoin] Testing join with FK values: ";
//        for (size_t i = 0; i < 8; ++i) {
//            std::cout << fk_values[i] << " ";
//        }
//        std::cout << std::endl;
//
//        // Encrypt FK values
//        auto pt_fk = cc->MakeCKKSPackedPlaintext(fk_values);
//        auto ct_fk = cc->Encrypt(pk, pt_fk);
//
//        // Step 1: Evaluate P(x) to get membership indicator
//        auto ct_P = cc->EvalPoly(ct_fk, coefP_orders);
//
//        // Step 2: Create membership mask: δ ≈ 1/(1 + P(x)²)
//        auto ct_P_squared = cc->EvalMult(ct_P, ct_P);
//        auto ct_denominator = cc->EvalAddConstant(ct_P_squared, 1.0);
//        auto ct_membership_mask = cc->EvalInv(ct_denominator);
//
//        // Step 3: Evaluate Q(x) to get payload values
//        auto ct_Q_orderdate = cc->EvalPoly(ct_fk, coefQ_orderdate);
//
//        // Step 4: Apply membership mask to payload
//        auto ct_masked_orderdate = cc->EvalMult(ct_membership_mask, ct_Q_orderdate);
//
//        // Decrypt results
//        Plaintext pt_membership, pt_orderdate, pt_masked_orderdate;
//        cc->Decrypt(sk, ct_membership_mask, &pt_membership);
//        cc->Decrypt(sk, ct_Q_orderdate, &pt_Q_orderdate);
//        cc->Decrypt(sk, ct_masked_orderdate, &pt_masked_orderdate);
//
//        auto membership_values = pt_membership->GetRealPackedValue();
//        auto orderdate_values = pt_Q_orderdate->GetRealPackedValue();
//        auto masked_orderdate_values = pt_masked_orderdate->GetRealPackedValue();
//
//        std::cout << "[PolyJoin] Join simulation results:" << std::endl;
//        std::cout << "FK\tMembership\tOrderDate\tMaskedOrderDate" << std::endl;
//        for (size_t i = 0; i < 8; ++i) {
//            std::cout << fk_values[i] << "\t"
//                      << membership_values[i] << "\t"
//                      << orderdate_values[i] << "\t"
//                      << masked_orderdate_values[i] << std::endl;
//        }
//
//        // Verify results
//        // Valid FK values (1-5) should have membership ≈ 1.0 and show orderdate values
//        // Invalid FK values (99, 100, 101) should have membership ≈ 0.0 and show 0
//        for (size_t i = 0; i < 5; ++i) {
//            EXPECT_GT(membership_values[i], 0.9) << "Valid FK " << fk_values[i] << " should have high membership";
//            EXPECT_GT(masked_orderdate_values[i], 0.0) << "Valid FK " << fk_values[i] << " should show orderdate";
//        }
//
//        for (size_t i = 5; i < 8; ++i) {
//            EXPECT_LT(membership_values[i], 0.1) << "Invalid FK " << fk_values[i] << " should have low membership";
//            EXPECT_NEAR(masked_orderdate_values[i], 0.0, 0.1) << "Invalid FK " << fk_values[i] << " should show 0 orderdate";
//        }
//
//        std::cout << "[PolyJoin] Polynomial-based join simulation test passed!" << std::endl;
//
//    } catch (const std::exception& e) {
//        FAIL() << "Exception during polynomial-based join simulation: " << e.what();
//    }
//}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
