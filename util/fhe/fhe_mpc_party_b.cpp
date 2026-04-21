#include "util/fhe/fhe_mpc_party_b.h"

#include <algorithm>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

#include "operators/columnar/secure_context_switch.h"
#include "util/type_utilities.h"
#include "operators/sort.h"
#include "query_table/columnar/fhe_column.h"
#include "query_table/columnar/fhe_column_chunk.h"
#include "query_table/columnar/fhe_column_table.h"
#include "query_table/query_table.h"
#include "util/crypto_manager/fhe_manager.h"
#include "util/fhe/fhe_helpers.h"
#include "util/fhe/fhe_network.h"
#include "util/google_test_flags.h"
#include "util/fhe/fhe_to_mpc_decrypt.h"
#include "util/crypto_manager/sh2pc_manager.h"

namespace vaultdb {

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
    int mpc_in_circuit_port) {
    if (!mpc_network_io) {
        throw std::runtime_error("[RunMpcPartyB] Party B: MPC network not initialized");
    }
    if (!result_table) {
        throw std::runtime_error("[RunMpcPartyB] Party B: Missing result table for MPC");
    }

    const auto& schema = result_table->getSchema();
    for (int col_idx : encrypted_col_indices) {
        if (col_idx != -1 && (col_idx < 0 || col_idx >= schema.getFieldCount())) {
            throw std::runtime_error("[Party B] RunMpcPartyB: invalid encrypted column index");
        }
    }
    const int num_agg_cols = static_cast<int>(encrypted_col_indices.size());

    if (!decryption_in_mpc) {
        size_t num_agg_columns_u = static_cast<size_t>(num_agg_cols);
        mpc_network_io->sendData(&num_agg_columns_u, sizeof(size_t));
        if (num_agg_cols == 0) {
            std::cout << "[Party B] No aggregate columns (sort-only plan), sending 0 to Party C" << std::endl;
            return std::vector<std::vector<int64_t>>();
        }
        if (FLAGS_debug) std::cout << "[Party B] Sending num_agg_columns=" << num_agg_columns_u << std::endl;

        std::vector<std::vector<int64_t>> r_values_per_column(static_cast<size_t>(num_agg_cols));
        for (size_t pos = 0; pos < encrypted_col_indices.size(); ++pos) {
            int col_idx = encrypted_col_indices[pos];
            const std::string col_name = (col_idx == -1) ? "dummy_tag" : schema.getField(col_idx).getName();
            auto enc_col = result_table->getFheColumn(col_name);
            if (!enc_col || enc_col->getFheChunks().empty()) {
                throw std::runtime_error("[Party B] Encrypted aggregate column not found: " + col_name);
            }
            const auto& chunks = enc_col->getFheChunks();
            size_t chunk_count = chunks.size();
            mpc_network_io->sendData(&chunk_count, sizeof(size_t));

            std::vector<int64_t>& all_r_values = r_values_per_column[pos];
            const size_t rns_level = enc_col->getRnsLevel();
            const auto& rns_moduli = (rns_level > 1) ? FheManager::getInstance().getRnsModuli() : std::vector<uint64_t>{};

            for (const auto& chunk : chunks) {
                if (!chunk) continue;
                size_t chunk_rns = chunk->getRnsLevel();
                if (chunk_rns == 0) continue;
                try {
                    size_t slot_count = chunk->packed_count;
                    mpc_network_io->sendData(&chunk_rns, sizeof(size_t));
                    mpc_network_io->sendData(&slot_count, sizeof(size_t));

                    if (chunk_rns == 1) {
                        auto ct = chunk->getCiphertext(0);
                        if (!ct) continue;
                        auto result = FheToMpcDecrypt::DecryptWithNoise(
                            mpc_network_io, cc, pk, sk_share, /*party=*/2,
                            ct, slot_count,
                            mpc_debug_masked_decrypt ? masked_ct_debug_serialized : nullptr);
                        const auto& r_values = result.party_b_values;
                        size_t n = std::min(r_values.size(), slot_count);
                        all_r_values.insert(all_r_values.end(), r_values.begin(), r_values.begin() + n);
                    } else {
                        if (rns_moduli.size() < chunk_rns)
                            throw std::runtime_error("[Party B] RNS moduli count < chunk rns_level");
                        std::vector<uint64_t> moduli(rns_moduli.begin(), rns_moduli.begin() + chunk_rns);
                        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> cts(chunk_rns);
                        for (size_t ch = 0; ch < chunk_rns; ++ch) {
                            auto ct = chunk->getCiphertext(ch);
                            if (!ct) throw std::runtime_error("[Party B] Missing ciphertext for channel " + std::to_string(ch));
                            cts[ch] = ct;
                        }
                        auto result = FheToMpcDecrypt::DecryptWithNoiseMultiChannel(
                            mpc_network_io, /*party=*/2, slot_count, moduli, &cts,
                            mpc_debug_masked_decrypt ? masked_ct_debug_serialized : nullptr);
                        const auto& r_values = result.party_b_values;
                        all_r_values.insert(all_r_values.end(), r_values.begin(), r_values.end());
                    }
                } catch (const std::exception& e) {
                    std::cout << "[Party B] Failed column " << col_name << ": " << e.what() << std::endl;
                    break;
                }
            }
            if (FLAGS_debug) std::cout << "[Party B] Column " << col_name << " R values: " << all_r_values.size() << std::endl;
        }
        if (FLAGS_debug) std::cout << "[Party B] Party B holds R only (does NOT know M or M-R)" << std::endl;
        return r_values_per_column;
    }

    // decryption_in_mpc path: single-column legacy (last aggregate column only) for compatibility
    if (encrypted_col_indices.empty()) {
        throw std::runtime_error("[Party B] RunMpcPartyB: decryption_in_mpc requires at least one encrypted column");
    }
    int count_col_idx = encrypted_col_indices.back();
    std::string count_col_name = schema.getField(count_col_idx).getName();
    auto enc_col = result_table->getFheColumn(count_col_name);
    if (!enc_col || enc_col->getFheChunks().empty()) {
        throw std::runtime_error("[RunMpcPartyB] Party B: Encrypted aggregate column not found");
    }
    const auto& chunks = enc_col->getFheChunks();
    size_t valid_chunk_count = 0;
    for (const auto& chunk : chunks) {
        if (!chunk || !chunk->getFheValue()) {
            continue;
        }
        auto test_ciphertext = chunk->getFheValue()->getCiphertext();
        if (!test_ciphertext) {
            continue;
        }
        ++valid_chunk_count;
    }
    if (FLAGS_debug) std::cout << "[Party B] Sending MPC valid_chunk_count=" << valid_chunk_count << std::endl;
    mpc_network_io->sendData(&valid_chunk_count, sizeof(size_t));
    if (FLAGS_debug) std::cout << "[Party B] MPC chunk_count sent." << std::endl;

    int original_party = SystemConfiguration::getInstance().party_;
    auto original_crypto_mode = SystemConfiguration::getInstance().crypto_mode_;
    if (FLAGS_debug) std::cout << "[Party B] Initializing SH2PCManager (EMP Setup) on port "
              << mpc_in_circuit_port << "..." << std::endl;
    SH2PCManager mpc_manager("", emp::ALICE, mpc_in_circuit_port);
    if (FLAGS_debug) std::cout << "[Party B] EMP Setup Complete!" << std::endl;

    auto sk_dcrt = sk_share->GetPrivateElement();
    sk_dcrt.SetFormat(Format::EVALUATION);
    std::vector<int64_t> revealed;
    uint64_t plain_modulus = cc->GetCryptoParameters()->GetPlaintextModulus();

    for (const auto& chunk : chunks) {
        if (!chunk || !chunk->getFheValue()) {
            continue;
        }
        auto test_ciphertext = chunk->getFheValue()->getCiphertext();
        if (!test_ciphertext) {
            continue;
        }

        auto elements = test_ciphertext->GetElements();
        if (elements.size() < 2) {
            continue;
        }
        size_t num_towers = elements[0].GetNumOfElements();
        size_t num_towers_to_process = num_towers;
        mpc_network_io->sendData(&num_towers_to_process, sizeof(size_t));
        std::vector<lbcrypto::NativePoly> w_towers(num_towers_to_process);

        for (size_t t_idx = 0; t_idx < num_towers_to_process; ++t_idx) {
            lbcrypto::NativePoly c0_poly = elements[0].GetElementAtIndex(t_idx);
            lbcrypto::NativePoly c1_poly = elements[1].GetElementAtIndex(t_idx);
            lbcrypto::NativePoly sk_poly = sk_dcrt.GetElementAtIndex(t_idx);

            c0_poly.SetFormat(Format::EVALUATION);
            c1_poly.SetFormat(Format::EVALUATION);
            sk_poly.SetFormat(Format::EVALUATION);

            auto c0_vec = ExtractPolyValues(c0_poly);
            auto c1_vec = ExtractPolyValues(c1_poly);

            size_t coeff_count = c0_vec.size();
            uint64_t q = c0_poly.GetModulus().ConvertToInt();
            uint64_t t = plain_modulus;

            auto normalize_vec = [&](std::vector<int64_t>& vals, uint64_t mod) {
                for (auto& v : vals) {
                    int64_t tmp = v % static_cast<int64_t>(mod);
                    if (tmp < 0) {
                        tmp += static_cast<int64_t>(mod);
                    }
                    v = tmp;
                }
            };
            normalize_vec(c0_vec, q);
            normalize_vec(c1_vec, q);

            std::vector<int64_t> u_b_vec(coeff_count);
            if (coeff_count > 0) {
                auto u_b_poly = c0_poly + (c1_poly * sk_poly);
                u_b_poly.SetFormat(Format::COEFFICIENT);
                u_b_vec = ExtractPolyValues(u_b_poly);
                normalize_vec(u_b_vec, q);
            }

            mpc_network_io->sendData(&coeff_count, sizeof(size_t));
            mpc_network_io->sendData(&q, sizeof(uint64_t));
            mpc_network_io->sendData(&t, sizeof(uint64_t));
            if (coeff_count > 0) {
                mpc_network_io->sendData(c0_vec.data(), coeff_count * sizeof(int64_t));
                mpc_network_io->sendData(c1_vec.data(), coeff_count * sizeof(int64_t));
            }

            if (FLAGS_debug) std::cout << "[Party B] Data sent. Starting in-circuit decryption (coeff_count="
                      << coeff_count << ")..." << std::endl;
            std::vector<int64_t> zero_vec(coeff_count, 0);
            std::vector<int64_t> mask_b(coeff_count, 0);
            if (coeff_count > 0) {
                std::mt19937_64 rng(0xBEEFCAFEULL + coeff_count + t_idx);
                std::uniform_int_distribution<uint64_t> dist(0, q - 1);
                for (size_t i = 0; i < coeff_count; ++i) {
                    mask_b[i] = static_cast<int64_t>(dist(rng));
                }
            }

            auto shares = mpc_manager.runInCircuitDecryption(
                u_b_vec, zero_vec, mask_b, zero_vec, q);
            if (FLAGS_debug) std::cout << "[Party B] Circuit execution finished." << std::endl;
            std::vector<int64_t> u_c_vec(coeff_count, 0);
            std::vector<int64_t> mask_c(coeff_count, 0);
            if (coeff_count > 0) {
                if (t_idx == 0) {
                    mpc_network_io->recvData(u_c_vec.data(), coeff_count * sizeof(int64_t));
                }
                mpc_network_io->recvData(mask_c.data(), coeff_count * sizeof(int64_t));
            }
            char sync = 1;
            mpc_network_io->recvData(&sync, sizeof(sync));
            mpc_network_io->sendData(&sync, sizeof(sync));

            std::vector<int64_t> masked_vec;
            masked_vec.reserve(shares.size());
            if (FLAGS_debug && t_idx == 0) {
                std::cout << "[Party B] Revealing and collecting shares..." << std::endl;
            }
            int count = 0;
            const int reveal_party = emp::PUBLIC;
            for (const auto& val : shares) {
                auto revealed_val = val.reveal<int64_t>(reveal_party);
                masked_vec.push_back(revealed_val);
                revealed.push_back(revealed_val);
                if (FLAGS_debug && t_idx == 0 && count < 5) {
                    std::cout << "[Party B] Raw Noisy[" << count << "]: "
                              << revealed_val << std::endl;
                }
                if (FLAGS_debug && t_idx == 0 && (count + 1) % 128 == 0) {
                    std::cout << "[Party B] Reveal progress: " << (count + 1)
                              << " / " << shares.size() << std::endl;
                    std::cout << std::flush;
                }
                ++count;
            }
            mpc_manager.flush();
            char sync_after = 1;
            mpc_network_io->recvData(&sync_after, sizeof(sync_after));
            mpc_network_io->sendData(&sync_after, sizeof(sync_after));

            const size_t share_count = masked_vec.size();
            std::vector<int64_t> w_vec(coeff_count, 0);
            for (size_t i = 0; i < share_count; ++i) {
                int64_t tmp = masked_vec[i] - mask_b[i] - mask_c[i];
                tmp %= static_cast<int64_t>(q);
                if (tmp < 0) {
                    tmp += static_cast<int64_t>(q);
                }
                w_vec[i] = tmp;
            }

            if (FLAGS_debug && share_count > 0 && t_idx == 0) {
                size_t mismatch_count = 0;
                for (size_t i = 0; i < share_count; ++i) {
                    int64_t tmp = u_b_vec[i] + u_c_vec[i];
                    tmp %= static_cast<int64_t>(q);
                    if (tmp < 0) {
                        tmp += static_cast<int64_t>(q);
                    }
                    if (tmp != w_vec[i]) {
                        if (mismatch_count < 5) {
                            std::cout << "[Party B] w_vec mismatch idx=" << i
                                      << " direct=" << tmp
                                      << " mpc=" << w_vec[i] << std::endl;
                        }
                        ++mismatch_count;
                    }
                }
                std::cout << "[Party B] w_vec compare done. mismatches=" << mismatch_count
                          << " of " << share_count << std::endl;
            }

            {
                auto params = c0_poly.GetParams();
                lbcrypto::NativeVector w_vals(params->GetRingDimension(), params->GetModulus());
                for (size_t i = 0; i < w_vec.size(); ++i) {
                    w_vals[i] = static_cast<uint64_t>(w_vec[i]);
                }
                lbcrypto::NativePoly w_poly(params);
                w_poly.SetValues(w_vals, Format::COEFFICIENT);
                w_towers[t_idx] = std::move(w_poly);
            }
        }

        if (!w_towers.empty()) {
            auto full_params = elements[0].GetParams();
            lbcrypto::DCRTPoly w_dcrt(full_params, Format::COEFFICIENT, false);
            const auto& tower_params = full_params->GetParams();
            for (size_t i = 0; i < tower_params.size(); ++i) {
                if (i < w_towers.size()) {
                    w_dcrt.SetElementAtIndex(i, w_towers[i]);
                } else {
                    lbcrypto::NativePoly zero_poly(tower_params[i], Format::COEFFICIENT, true);
                    w_dcrt.SetElementAtIndex(i, zero_poly);
                }
            }

            auto big_poly = w_dcrt.CRTInterpolate();
            const auto& big_vals = big_poly.GetValues();
            auto big_Q = big_poly.GetParams()->GetModulus();
            auto big_t = decltype(big_Q)(plain_modulus);
            auto half_Q = big_Q / 2;

            std::vector<int64_t> messages;
            messages.reserve(big_vals.GetLength());
            for (size_t i = 0; i < big_vals.GetLength(); ++i) {
                auto scaled = (big_vals[i] * big_t + half_Q) / big_Q;
                auto mod_t = scaled % big_t;
                messages.push_back(static_cast<int64_t>(mod_t.ConvertToInt()));
            }

            if (FLAGS_debug) {
                std::cout << "---- [DEBUG MPC CRT+ROUND RESULTS] ----" << std::endl;
                std::cout << "Decrypted Values (First 20): " << std::endl;
                for (size_t i = 0; i < std::min(static_cast<size_t>(20), messages.size()); ++i) {
                    std::cout << "Idx[" << i << "]: " << messages[i] << std::endl;
                }
                std::cout << "---------------------------------------" << std::endl;
            }

            auto params_t = std::make_shared<lbcrypto::ILNativeParams>(
                elements[0].GetElementAtIndex(0).GetParams()->GetCyclotomicOrder(),
                lbcrypto::NativeInteger(plain_modulus), 1);
            lbcrypto::NativeVector m_vals(params_t->GetRingDimension(), params_t->GetModulus());
            for (size_t i = 0; i < messages.size(); ++i) {
                uint64_t v = static_cast<uint64_t>(messages[i] % static_cast<int64_t>(plain_modulus));
                m_vals[i] = v;
            }
            lbcrypto::NativePoly m_poly(params_t);
            m_poly.SetValues(m_vals, Format::COEFFICIENT);
            auto decoded_slots = DecodePackedValuesFromNativePoly(
                m_poly, cc);

            if (FLAGS_debug) {
                std::cout << "---- [DEBUG MPC PACKED SLOTS] ----" << std::endl;
                std::cout << "Slots (First 20): " << std::endl;
                for (size_t i = 0; i < std::min(static_cast<size_t>(20), decoded_slots.size()); ++i) {
                    std::cout << "Slot[" << i << "]: " << decoded_slots[i] << std::endl;
                }
                std::cout << "----------------------------------" << std::endl;
            }
        }
    }

    SystemConfiguration::getInstance().party_ = original_party;
    SystemConfiguration::getInstance().crypto_mode_ = original_crypto_mode;

    if (FLAGS_debug) {
        std::cout << "========== [PARTY B MPC DECRYPT] ==========" << std::endl;
        std::cout << "Party B MPC Decrypt (public): ";
        for (size_t i = 0; i < std::min(static_cast<size_t>(10), revealed.size()); ++i) {
            std::cout << revealed[i] << " ";
        }
        std::cout << "\n==========================================" << std::endl;
    }
    std::vector<std::vector<int64_t>> result(1);
    result[0] = std::move(revealed);
    return result;  // Legacy single-column for decryption_in_mpc
}

void SendResultModeHeader(FheNetworkIO* to_a, int32_t mode) {
    if (!to_a) {
        throw std::runtime_error("[Party B] SendResultModeHeader: null network IO");
    }
    to_a->sendData(&mode, sizeof(int32_t));
}

namespace {
/// First column index whose name starts with "sum_" or "count_" is the first aggregate column.
int getGroupByCountFromSchema(const QuerySchema& schema) {
    for (int i = 0; i < schema.getFieldCount(); ++i) {
        const std::string& name = schema.getField(i).getName();
        if (name.find("sum_") == 0 || name.find("count_") == 0) {
            return i;
        }
    }
    return schema.getFieldCount();
}
}  // namespace

void SendSharesToPartyA(SecureTable* table, FheNetworkIO* to_a, const QuerySchema* display_schema,
                        const std::vector<int64_t>* precomputed_shares) {
    if (!table || !to_a) {
        throw std::runtime_error("[Party B] SendSharesToPartyA: null table or network IO");
    }
    std::vector<int64_t> flat_shares;
    if (precomputed_shares != nullptr) {
        flat_shares = *precomputed_shares;
    } else {
        flat_shares = extractAllLocalShares(table);
    }
    const QuerySchema& schema = table->getSchema();
    std::vector<int> ordinals;
    for (const auto& kv : schema.fields_) {
        ordinals.push_back(kv.first);
    }
    if (table->column_data_.find(-1) != table->column_data_.end()) {
        if (std::find(ordinals.begin(), ordinals.end(), -1) == ordinals.end()) {
            ordinals.push_back(-1);
        }
    }
    std::sort(ordinals.begin(), ordinals.end());
    int field_count = static_cast<int>(ordinals.size());
    size_t row_count = table->tuple_cnt_;
    int group_by_count = getGroupByCountFromSchema(schema);
    to_a->sendData(&field_count, sizeof(int));
    to_a->sendData(&row_count, sizeof(size_t));
    to_a->sendData(&group_by_count, sizeof(int));
    const bool use_display_types = (display_schema != nullptr && display_schema->getFieldCount() == field_count);
    for (size_t pos = 0; pos < ordinals.size(); ++pos) {
        int i = ordinals[pos];
        auto it = schema.fields_.find(i);
        if (it == schema.fields_.end()) {
            if (i == -1) {
                to_a->sendString("dummy_tag");
                int ft = static_cast<int>(FieldType::LONG);
                to_a->sendData(&ft, sizeof(int));
                to_a->sendString("");
                int sl = 0;
                to_a->sendData(&sl, sizeof(int));
            }
            continue;
        }
        const auto& f = it->second;
        to_a->sendString(f.getName());
        FieldType ft_send = use_display_types ? display_schema->getField(static_cast<int>(pos)).getType() : TypeUtilities::toPlain(f.getType());
        int ft = static_cast<int>(ft_send);
        to_a->sendData(&ft, sizeof(int));
        to_a->sendString(f.getTableName());
        int sl = static_cast<int>(f.getStringLength());
        to_a->sendData(&sl, sizeof(int));
    }
    size_t n = flat_shares.size();
    to_a->sendData(&n, sizeof(size_t));
    if (n > 0) to_a->sendData(flat_shares.data(), n * sizeof(int64_t));
}

void SyncWithPartyC(FheNetworkIO* io) {
    if (!io) return;
    char sync_byte = 0;
    io->sendData(&sync_byte, 1);
    io->recvData(&sync_byte, 1);
}

namespace {
SecureContextSwitch* findSecureContextSwitchOp(Operator<emp::Bit>* op) {
    if (!op) return nullptr;
    if (auto* scs = dynamic_cast<SecureContextSwitch*>(op)) return scs;
    if (auto* left = findSecureContextSwitchOp(op->getChild(0))) return left;
    return findSecureContextSwitchOp(op->getChild(1));
}
} // namespace

void SyncWithPartyC(MpcHostingOperator* host) {
    if (!host) return;
    Operator<emp::Bit>* root_mpc_op = host->getRealMpcOp();
    auto* scs = findSecureContextSwitchOp(root_mpc_op);
    if (scs) SyncWithPartyC(scs->getMpcNetworkIO());
}

} // namespace vaultdb
