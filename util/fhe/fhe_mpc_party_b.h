#ifndef _FHE_MPC_PARTY_B_H_
#define _FHE_MPC_PARTY_B_H_

#include <cstdint>
#include <memory>
#include <string>

#include "openfhe.h"
#include "query_table/query_schema.h"
#include "query_table/query_table.h"
#include "operators/columnar/mpc_hosting_operator.h"

namespace vaultdb {
class FheColumnTable;
class FheNetworkIO;

/// Send 4-byte result-mode header to Party A before payload. Must match protocol.
void SendResultModeHeader(FheNetworkIO* to_a, int32_t mode);

/// Decrypt encrypted columns (in the provided schema-index order) and run B/C protocol.
/// Returns R values per column aligned with encrypted_col_indices.
std::vector<std::vector<int64_t>> RunMpcPartyB(
    FheNetworkIO* mpc_network_io,
    const std::shared_ptr<FheColumnTable>& result_table,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& pk,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk_share,
    const std::vector<int>& encrypted_col_indices,
    bool decryption_in_mpc,
    bool mpc_debug_masked_decrypt,
    std::string* masked_ct_debug_serialized,
    int mpc_in_circuit_port);

/// When display_schema is non-null and has same field count as table, sends its field types to A so decimal columns are shown as value/10^6.
void SendSharesToPartyA(SecureTable* table, FheNetworkIO* to_a, const QuerySchema* display_schema = nullptr,
                        const std::vector<int64_t>* precomputed_shares = nullptr);
void SyncWithPartyC(FheNetworkIO* io);
void SyncWithPartyC(MpcHostingOperator* host);
} // namespace vaultdb

#endif // _FHE_MPC_PARTY_B_H_
