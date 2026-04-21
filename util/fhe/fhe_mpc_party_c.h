#ifndef _FHE_MPC_PARTY_C_H_
#define _FHE_MPC_PARTY_C_H_

#include <string>
#include <vector>

#include "openfhe.h"

namespace vaultdb {
class FheNetworkIO;

/// Returns M-R per aggregate column (one vector per column) for MPC. Protocol: receive
/// num_agg_columns, then for each column receive chunk_count and per-chunk slot_count + DecryptWithNoise.
std::vector<std::vector<int64_t>> RunMpcPartyC(
    FheNetworkIO* mpc_network_io,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& pk,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk_share,
    bool decryption_in_mpc);

/// Standalone Party C: listen (SCS) -> receive -> Sort -> extract shares -> send to A -> sync with B.
/// Caller must set PlanParser party-A crypto context/key share before calling.
void RunStandalonePartyC(int mpc_port, const std::string& charlie_host, bool decryption_in_mpc,
                        int mpc_in_circuit_port, FheNetworkIO* to_party_a);
} // namespace vaultdb

#endif // _FHE_MPC_PARTY_C_H_
