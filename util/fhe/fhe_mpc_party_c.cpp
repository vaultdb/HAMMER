#include "util/fhe/fhe_mpc_party_c.h"

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <gflags/gflags.h>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

#include "operators/columnar/secure_context_switch.h"
#include "operators/sort.h"
#include "util/crypto_manager/fhe_manager.h"
#include "util/fhe/fhe_helpers.h"
#include "util/fhe/fhe_network.h"
#include "util/fhe/fhe_to_mpc_decrypt.h"
#include "util/crypto_manager/sh2pc_manager.h"
#include "util/system_configuration.h"
#include "util/google_test_flags.h"

DECLARE_string(fhe_bob_host);
DECLARE_int32(fhe_mpc_in_circuit_port);

namespace vaultdb {

std::vector<std::vector<int64_t>> RunMpcPartyC(
    FheNetworkIO* mpc_network_io,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& pk,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk_share,
    bool decryption_in_mpc) {
    if (!mpc_network_io) {
        throw std::runtime_error("[RunMpcPartyC] Party C: MPC network not initialized");
    }

    if (!decryption_in_mpc) {
        size_t num_agg_columns = 0;
        mpc_network_io->recvData(&num_agg_columns, sizeof(size_t));
        if (FLAGS_debug) std::cout << "[Party C] num_agg_columns received: " << num_agg_columns << std::endl;

        std::vector<std::vector<int64_t>> m_minus_r_per_column(num_agg_columns);
        const auto& rns_moduli = FheManager::getInstance().getRnsModuli();
        for (size_t col = 0; col < num_agg_columns; ++col) {
            size_t chunk_count = 0;
            mpc_network_io->recvData(&chunk_count, sizeof(size_t));
            std::vector<int64_t>& all_m_minus_r = m_minus_r_per_column[col];
            for (size_t idx = 0; idx < chunk_count; ++idx) {
                size_t chunk_rns = 0;
                mpc_network_io->recvData(&chunk_rns, sizeof(size_t));
                size_t slot_count = 0;
                mpc_network_io->recvData(&slot_count, sizeof(size_t));
                if (chunk_rns == 1) {
                    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> dummy_ct;
                    auto result = FheToMpcDecrypt::DecryptWithNoise(
                        mpc_network_io, cc, pk, sk_share, /*party=*/3, dummy_ct, slot_count);
                    const auto& m_minus_r = result.party_c_values;
                    size_t n = std::min(m_minus_r.size(), slot_count);
                    all_m_minus_r.insert(all_m_minus_r.end(), m_minus_r.begin(), m_minus_r.begin() + n);
                } else {
                    if (rns_moduli.size() < chunk_rns)
                        throw std::runtime_error("[Party C] RNS moduli count < chunk rns_level");
                    std::vector<uint64_t> moduli(rns_moduli.begin(), rns_moduli.begin() + chunk_rns);
                    auto result = FheToMpcDecrypt::DecryptWithNoiseMultiChannel(
                        mpc_network_io, /*party=*/3, slot_count, moduli, nullptr);
                    all_m_minus_r.insert(all_m_minus_r.end(), result.party_c_values.begin(), result.party_c_values.end());
                }
            }
            if (FLAGS_debug) std::cout << "[Party C] Column " << col << " M-R count: " << all_m_minus_r.size() << std::endl;
        }

        if (FLAGS_debug) std::cout << "[Party C] Party C holds M-R only (does NOT know R or M)" << std::endl;
        return m_minus_r_per_column;
    }

    size_t chunk_count = 0;
    if (FLAGS_debug) std::cout << "[Party C] Waiting for MPC chunk_count..." << std::endl;
    mpc_network_io->recvData(&chunk_count, sizeof(size_t));
    if (FLAGS_debug) std::cout << "[Party C] MPC chunk_count received: " << chunk_count << std::endl;

    std::string alice_host = FLAGS_fhe_bob_host.empty() ? "127.0.0.1" : FLAGS_fhe_bob_host;
    int original_party = SystemConfiguration::getInstance().party_;
    auto original_crypto_mode = SystemConfiguration::getInstance().crypto_mode_;
    if (FLAGS_debug) std::cout << "[Party C] Initializing SH2PCManager (EMP Setup) connecting to "
              << alice_host << ":" << FLAGS_fhe_mpc_in_circuit_port << "..." << std::endl;
    SH2PCManager mpc_manager(alice_host, emp::BOB, FLAGS_fhe_mpc_in_circuit_port);
    if (FLAGS_debug) std::cout << "[Party C] EMP Setup Complete!" << std::endl;

    auto sk_dcrt = sk_share->GetPrivateElement();
    sk_dcrt.SetFormat(Format::EVALUATION);
    std::vector<int64_t> revealed;

    for (size_t idx = 0; idx < chunk_count; ++idx) {
        size_t num_towers = 0;
        mpc_network_io->recvData(&num_towers, sizeof(size_t));

        for (size_t t_idx = 0; t_idx < num_towers; ++t_idx) {
            size_t coeff_count = 0;
            uint64_t q = 0;
            uint64_t t = 0;
            mpc_network_io->recvData(&coeff_count, sizeof(size_t));
            mpc_network_io->recvData(&q, sizeof(uint64_t));
            mpc_network_io->recvData(&t, sizeof(uint64_t));

            std::vector<int64_t> c0_vec(coeff_count);
            std::vector<int64_t> c1_vec(coeff_count);
            if (coeff_count > 0) {
                mpc_network_io->recvData(c0_vec.data(), coeff_count * sizeof(int64_t));
                mpc_network_io->recvData(c1_vec.data(), coeff_count * sizeof(int64_t));
            }

            if (FLAGS_debug) std::cout << "[Party C] Data received. Starting in-circuit decryption (coeff_count="
                      << coeff_count << ")..." << std::endl;
            auto sk_poly = sk_dcrt.GetElementAtIndex(t_idx);
            sk_poly.SetFormat(Format::EVALUATION);

            auto normalize_vec = [&](std::vector<int64_t>& vals, uint64_t mod) {
                for (auto& v : vals) {
                    int64_t tmp = v % static_cast<int64_t>(mod);
                    if (tmp < 0) {
                        tmp += static_cast<int64_t>(mod);
                    }
                    v = tmp;
                }
            };
            normalize_vec(c1_vec, q);

            std::vector<int64_t> u_c_vec(coeff_count);
            if (coeff_count > 0) {
                auto params = sk_poly.GetParams();
                lbcrypto::NativeVector c1_values(params->GetRingDimension(), params->GetModulus());
                for (size_t i = 0; i < coeff_count; ++i) {
                    c1_values[i] = static_cast<uint64_t>(c1_vec[i]);
                }
                lbcrypto::NativePoly c1_poly(params);
                c1_poly.SetValues(c1_values, Format::EVALUATION);

                auto u_c_poly = c1_poly * sk_poly;
                u_c_poly.SetFormat(Format::COEFFICIENT);
                u_c_vec = ExtractPolyValues(u_c_poly);
                normalize_vec(u_c_vec, q);
            }

            std::vector<int64_t> zero_vec(coeff_count, 0);
            std::vector<int64_t> mask_c(coeff_count, 0);
            if (coeff_count > 0) {
                std::mt19937_64 rng(0xC0FFEEULL + coeff_count + t_idx);
                std::uniform_int_distribution<uint64_t> dist(0, q - 1);
                for (size_t i = 0; i < coeff_count; ++i) {
                    mask_c[i] = static_cast<int64_t>(dist(rng));
                }
            }

            auto shares = mpc_manager.runInCircuitDecryption(
                zero_vec, u_c_vec, zero_vec, mask_c, q);
            if (FLAGS_debug) std::cout << "[Party C] Circuit execution finished." << std::endl;

            if (coeff_count > 0) {
                if (t_idx == 0) {
                    mpc_network_io->sendData(u_c_vec.data(), coeff_count * sizeof(int64_t));
                }
                mpc_network_io->sendData(mask_c.data(), coeff_count * sizeof(int64_t));
            }

            char sync = 1;
            mpc_network_io->sendData(&sync, sizeof(sync));
            mpc_network_io->recvData(&sync, sizeof(sync));

            if (FLAGS_debug) std::cout << "[Party C] Revealing shares..." << std::endl;
            int count = 0;
            const int reveal_party = emp::PUBLIC;
            for (const auto& val : shares) {
                auto revealed_val = val.reveal<int64_t>(reveal_party);
                revealed.push_back(revealed_val);
                if (FLAGS_debug && t_idx == 0 && count < 5) {
                    std::cout << "[Party C] Raw Share[" << count << "]: "
                              << revealed_val << std::endl;
                }
                if (FLAGS_debug && t_idx == 0 && (count + 1) % 128 == 0) {
                    std::cout << "[Party C] Reveal progress: " << (count + 1)
                              << " / " << shares.size() << std::endl;
                    std::cout << std::flush;
                }
                ++count;
            }
            mpc_manager.flush();
            if (FLAGS_debug && t_idx == 0) {
                std::cout << "[Party C] Reveal finished. Total: "
                          << revealed.size() << std::endl;
            }
            char sync_after = 1;
            mpc_network_io->sendData(&sync_after, sizeof(sync_after));
            mpc_network_io->recvData(&sync_after, sizeof(sync_after));
        }
    }

    SystemConfiguration::getInstance().party_ = original_party;
    SystemConfiguration::getInstance().crypto_mode_ = original_crypto_mode;

    if (FLAGS_debug) {
        std::cout << "========== [PARTY C MPC DECRYPT] ==========" << std::endl;
        std::cout << "Party C MPC Decrypt (public): ";
        for (size_t i = 0; i < std::min(static_cast<size_t>(10), revealed.size()); ++i) {
            std::cout << revealed[i] << " ";
        }
        std::cout << "\n==========================================\n" << std::endl;
    }
    std::vector<std::vector<int64_t>> result(1);
    result[0] = std::move(revealed);
    return result;  // Legacy single-column for decryption_in_mpc
}

void RunStandalonePartyC(int mpc_port, const std::string& charlie_host, bool decryption_in_mpc,
                        int mpc_in_circuit_port, FheNetworkIO* to_party_a) {
    if (!to_party_a) {
        throw std::runtime_error("[Party C] RunStandalonePartyC: to_party_a is null");
    }
    SecureContextSwitch context_switch(mpc_port, charlie_host, decryption_in_mpc, mpc_in_circuit_port);
    context_switch.runSelf();

    SecureTable* secure_table = context_switch.getSecureTable();
    if (!secure_table) {
        std::cout << "[Party C] No MPC handover required for this plan. Exiting Party C." << std::endl;
        return;
    }

    SortDefinition sort_def = context_switch.getSortDefinition();
    int limit = context_switch.getLimit();
    if (sort_def.empty()) {
        int sort_col = static_cast<int>(secure_table->getSchema().getFieldCount()) - 1;
        sort_def.push_back({sort_col, SortDirection::DESCENDING});
    }
    Sort<emp::Bit> sort_run(secure_table, sort_def, limit);
    SecureTable* sorted_table = sort_run.runSelf();

    if (SystemConfiguration::getInstance().hasMpc()) {
        SystemConfiguration::getInstance().mpc()->flush();
    }

    // Sync with B on 8777 so both enter next step in lockstep.
    FheNetworkIO* io = context_switch.getMpcNetworkIO();
    if (io) {
        char sync_byte = 0;
        io->recvData(&sync_byte, 1);
        io->sendData(&sync_byte, 1);
    }

    std::vector<int64_t> flat_shares = extractAllLocalShares(sorted_table);

    size_t share_count = flat_shares.size();
    to_party_a->sendData(&share_count, sizeof(size_t));
    if (share_count > 0) {
        to_party_a->sendData(flat_shares.data(), share_count * sizeof(int64_t));
    }
    std::fflush(stdout);
    /* Return normally so TearDown runs and next test can use fresh SetUp (listen again) */
}

} // namespace vaultdb
