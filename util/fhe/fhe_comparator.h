#ifndef _FHE_COMPARATOR_H_
#define _FHE_COMPARATOR_H_

#include "openfhe.h"
#include <vector>
#include <cmath>
#include <util/system_configuration.h>
#include <util/crypto_manager/fhe_manager.h>

namespace vaultdb {

    using namespace lbcrypto;

    inline FheManager& getFheManager() {
        auto* base = SystemConfiguration::getInstance().crypto_manager_;
        auto* manager = dynamic_cast<FheManager*>(base);
        if (!manager) {
            throw std::runtime_error("FHE comparator: FheManager is not configured.");
        }
        return *manager;
    }

    inline Ciphertext<DCRTPoly> comp_equal(const Ciphertext<DCRTPoly>& lhs, const Ciphertext<DCRTPoly>& rhs) {
        FheManager& manager = getFheManager();
        auto cc = manager.getRealCryptoContext();

        auto diff = cc->EvalSub(lhs, rhs);
        auto sq   = cc->EvalMult(diff, diff);
        auto inv  = cc->EvalSub(1.0, sq);
        return inv;
    }

    inline Ciphertext<DCRTPoly> comp_greater_than_modular(const Ciphertext<DCRTPoly>& lhs, const Ciphertext<DCRTPoly>& rhs) {
        FheManager& manager = getFheManager();
        auto cc = manager.getRealCryptoContext();

        auto lhs_minus_rhs = cc->EvalSub(lhs, rhs);
        Ciphertext<DCRTPoly> sign = cc->EvalMult(lhs_minus_rhs, lhs_minus_rhs);
        return sign;
    }

    inline Ciphertext<DCRTPoly> comp_not(const Ciphertext<DCRTPoly>& ct) {
        auto cc = getFheManager().getRealCryptoContext();
        return cc->EvalSub(1.0, ct);
    }

    inline Ciphertext<DCRTPoly> comp_or(const Ciphertext<DCRTPoly>& a, const Ciphertext<DCRTPoly>& b) {
        auto cc = getFheManager().getRealCryptoContext();
        auto sum = cc->EvalAdd(a, b);
        auto product = cc->EvalMult(a, b);
        return cc->EvalSub(sum, product);
    }

    inline Ciphertext<DCRTPoly> bfv_compare_gt_p17(
            const CryptoContext<DCRTPoly>& cc,
            const PublicKey<DCRTPoly>& pk,
            const Ciphertext<DCRTPoly>& diff_cipher,
            Ciphertext<DCRTPoly>& z_to_p_minus_1) {
        const int64_t exponent = 16;

        FheManager& fhe_manager = FheManager::getInstance();
        size_t pack_slots = fhe_manager.getBFVComparisonBatchSize();

        Ciphertext<DCRTPoly> z2 = cc->EvalMult(diff_cipher, diff_cipher);
        Ciphertext<DCRTPoly> z4 = cc->EvalMult(z2, z2);
        Ciphertext<DCRTPoly> z8 = cc->EvalMult(z4, z4);
        Ciphertext<DCRTPoly> z16 = cc->EvalMult(z8, z8);

        z_to_p_minus_1 = z16;

        std::vector<Ciphertext<DCRTPoly>> leaves;
        leaves.reserve(8);
        for (int64_t a = 9; a <= 16; ++a) {
            std::vector<int64_t> val_vec(pack_slots, a);
            Plaintext val_plain = cc->MakePackedPlaintext(val_vec);
            leaves.push_back(cc->EvalSub(diff_cipher, val_plain));
        }

        std::vector<Ciphertext<DCRTPoly>> level1;
        for (size_t i = 0; i < leaves.size(); i += 2) {
            auto prod = cc->EvalMult(leaves[i], leaves[i+1]);
            level1.push_back(prod);
        }

        std::vector<Ciphertext<DCRTPoly>> level2;
        for (size_t i = 0; i < level1.size(); i += 2) {
            auto prod = cc->EvalMult(level1[i], level1[i+1]);
            level2.push_back(prod);
        }

        Ciphertext<DCRTPoly> product = cc->EvalMult(level2[0], level2[1]);

        Ciphertext<DCRTPoly> ind_2 = cc->EvalMult(product, product);
        Ciphertext<DCRTPoly> ind_4 = cc->EvalMult(ind_2, ind_2);
        Ciphertext<DCRTPoly> ind_8 = cc->EvalMult(ind_4, ind_4);
        Ciphertext<DCRTPoly> indicator_powered = cc->EvalMult(ind_8, ind_8);

        Ciphertext<DCRTPoly> gt_result = cc->EvalMult(indicator_powered, z_to_p_minus_1);

        return gt_result;
    }

    inline Ciphertext<DCRTPoly> bfv_compare_gt(
            const Ciphertext<DCRTPoly>& ct_a,
            const Ciphertext<DCRTPoly>& ct_b,
            size_t pack_slots) {
        FheManager& manager = FheManager::getInstance();
        auto cc = manager.getComparisonCryptoContext();
        auto pk = manager.getComparisonPublicKey();

        Ciphertext<DCRTPoly> diff = cc->EvalSub(ct_a, ct_b);

        Ciphertext<DCRTPoly> z_to_p_minus_1;
        return bfv_compare_gt_p17(cc, pk, diff, z_to_p_minus_1);
    }

}  // namespace vaultdb

#endif  // _FHE_COMPARATOR_H_
