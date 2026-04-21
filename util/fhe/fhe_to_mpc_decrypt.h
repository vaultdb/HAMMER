#ifndef _FHE_TO_MPC_DECRYPT_H_
#define _FHE_TO_MPC_DECRYPT_H_

#include <memory>
#include <string>
#include <vector>

#include "openfhe.h"
#include "util/fhe/fhe_network.h"

namespace vaultdb {

struct FheToMpcDecryptResult {
    std::vector<int64_t> party_b_values;
    std::vector<int64_t> party_c_values;
};

class FheToMpcDecrypt {
public:
    static FheToMpcDecryptResult DecryptWithNoise(
        FheNetworkIO* mpc_network_io,
        const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
        const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& pk,
        const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk_share,
        int party,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_result,
        size_t num_slots,
        std::string* masked_ct_serialized = nullptr);

    /// Multi-channel: one raw R per slot, decomposed into residues r_i = R % moduli[i],
    /// encrypted per channel, then Enc(M) - Enc(R) sent to C. B keeps raw_R for MPC.
    /// \param cts_for_party_b  Only used when party==2: one ciphertext per channel (size must match moduli).
    static FheToMpcDecryptResult DecryptWithNoiseMultiChannel(
        FheNetworkIO* mpc_network_io,
        int party,
        size_t slot_count,
        const std::vector<uint64_t>& moduli,
        const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>* cts_for_party_b,
        std::string* masked_ct_serialized = nullptr);
};

} // namespace vaultdb

#endif // _FHE_TO_MPC_DECRYPT_H_
