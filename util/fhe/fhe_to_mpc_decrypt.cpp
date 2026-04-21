#include "util/fhe/fhe_to_mpc_decrypt.h"

#include <chrono>
#include <random>
#include <sstream>

#include <omp.h>
#include <openfhe/core/utils/serial.h>
#include <openfhe/pke/ciphertext-ser.h>
#include <openfhe/pke/encoding/packedencoding.h>
#include "util/google_test_flags.h"

#include "util/crypto_manager/fhe_manager.h"
#include "util/fhe/fhe_helpers.h"

using namespace lbcrypto;

namespace vaultdb {

FheToMpcDecryptResult FheToMpcDecrypt::DecryptWithNoise(
    FheNetworkIO* mpc_network_io,
    const CryptoContext<DCRTPoly>& cc,
    const PublicKey<DCRTPoly>& pk,
    const PrivateKey<DCRTPoly>& sk_share,
    int party,
    const Ciphertext<DCRTPoly>& ct_result,
    size_t num_slots,
    std::string* masked_ct_serialized) {

    if (!mpc_network_io) {
        throw std::runtime_error("DecryptWithNoiseOptimized: MPC network not initialized");
    }

    if (party == 2) {
        // Step 2 (single-channel): one 58-bit R per slot; Step 4: B keeps R as Val_B.
        std::vector<int64_t> r_vector(num_slots);
        std::random_device rd;
        auto seed = rd() ^ static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        std::mt19937_64 rng(seed);
        constexpr uint64_t kMaxR = (1ULL << 58) - 1ULL;
        std::uniform_int_distribution<uint64_t> dist(0, kMaxR);
        for (size_t i = 0; i < num_slots; ++i) {
            r_vector[i] = static_cast<int64_t>(dist(rng));
        }

        if (FLAGS_debug) {
            std::cout << "[Party B] Step2 single-channel R (first 5): ";
            for (size_t i = 0; i < std::min(size_t(5), r_vector.size()); ++i) {
                std::cout << r_vector[i] << " ";
            }
            std::cout << std::endl;
        }

        // Step 3: FHE computes Enc(M) - Enc(R) and sends Enc(M-R) to C.
        Plaintext pt_r = cc->MakePackedPlaintext(r_vector);
        auto ct_masked = cc->EvalSub(ct_result, pt_r);

        if (masked_ct_serialized) {
            std::ostringstream ct_oss;
            Serial::Serialize(ct_masked, ct_oss, SerType::BINARY);
            *masked_ct_serialized = ct_oss.str();
        }

        std::ostringstream ct_masked_oss;
        Serial::Serialize(ct_masked, ct_masked_oss, SerType::BINARY);
        mpc_network_io->sendString(ct_masked_oss.str());

        auto ct_partial_B = cc->MultipartyDecryptLead({ct_masked}, sk_share).at(0);

        std::ostringstream share_oss;
        Serial::Serialize(ct_partial_B, share_oss, SerType::BINARY);
        mpc_network_io->sendString(share_oss.str());

        if (FLAGS_debug) std::cout << "[Party B] Step3: Enc(M-R) and partial share sent to C. Step4: Val_B = R held." << std::endl;

        return {r_vector, std::vector<int64_t>{}};
    }

    if (party == 3) {
        std::string ct_masked_str = mpc_network_io->recvString();
        std::istringstream ct_masked_iss(ct_masked_str);
        Ciphertext<DCRTPoly> ct_masked;
        Serial::Deserialize(ct_masked, ct_masked_iss, SerType::BINARY);

        std::string share_str = mpc_network_io->recvString();
        std::istringstream share_iss(share_str);
        Ciphertext<DCRTPoly> ct_partial_B;
        Serial::Deserialize(ct_partial_B, share_iss, SerType::BINARY);

        auto ct_partial_C = cc->MultipartyDecryptMain({ct_masked}, sk_share).at(0);

        NativePoly result_poly;
        cc->GetScheme()->MultipartyDecryptFusion({ct_partial_B, ct_partial_C}, &result_poly);
        auto m_minus_r_values = DecodePackedValuesFromNativePoly(result_poly, cc);
        if (num_slots > 0 && m_minus_r_values.size() > num_slots) {
            m_minus_r_values.resize(num_slots);
        }

        if (FLAGS_debug) {
            std::cout << "[Party C] Step4: Val_C = M-R (first 5): ";
            for (size_t i = 0; i < std::min(size_t(5), m_minus_r_values.size()); ++i) {
                std::cout << m_minus_r_values[i] << " ";
            }
            std::cout << std::endl;
        }

        return {std::vector<int64_t>{}, m_minus_r_values};
    }

    throw std::runtime_error("DecryptWithNoise: Invalid party");
}

namespace {

// Generate one 58-bit random R per slot (R < 2^58, fits in int64_t and below typical P_total).
void GenerateRawRPerSlot(size_t num_slots, std::vector<uint64_t>& raw_r_out) {
    raw_r_out.resize(num_slots);
    std::random_device rd;
    auto seed = rd() ^ static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    std::mt19937_64 rng(seed);
    constexpr uint64_t kMaxR = (1ULL << 58) - 1ULL;
    std::uniform_int_distribution<uint64_t> dist(0, kMaxR);
    for (size_t i = 0; i < num_slots; ++i) {
        raw_r_out[i] = dist(rng);
    }
}

} // namespace

FheToMpcDecryptResult FheToMpcDecrypt::DecryptWithNoiseMultiChannel(
    FheNetworkIO* mpc_network_io,
    int party,
    size_t slot_count,
    const std::vector<uint64_t>& moduli,
    const std::vector<Ciphertext<DCRTPoly>>* cts_for_party_b,
    std::string* masked_ct_serialized) {

    if (!mpc_network_io) {
        throw std::runtime_error("DecryptWithNoiseMultiChannel: MPC network not initialized");
    }
    if (moduli.size() == 0) {
        throw std::runtime_error("DecryptWithNoiseMultiChannel: moduli empty");
    }
    const size_t num_channels = moduli.size();

    if (party == 2) {
        if (!cts_for_party_b || cts_for_party_b->size() != num_channels) {
            throw std::runtime_error("DecryptWithNoiseMultiChannel: party 2 requires cts size == moduli size");
        }
        std::vector<uint64_t> raw_r(slot_count);
        GenerateRawRPerSlot(slot_count, raw_r);

        if (FLAGS_debug) {
            std::cout << "[Party B] Step2 multi-channel: one raw R per slot (first 5): ";
            for (size_t i = 0; i < std::min(size_t(5), raw_r.size()); ++i) {
                std::cout << raw_r[i] << " ";
            }
            std::cout << std::endl;
        }

        // Step 3: Per channel, compute Enc(M)-Enc(R) and partial decrypt share.
        // Phase 1: Parallel crypto + serialization (each channel uses an independent CryptoContext).
        std::vector<std::string> ct_masked_strs(num_channels);
        std::vector<std::string> partial_strs(num_channels);

        #pragma omp parallel for schedule(static)
        for (size_t ch = 0; ch < num_channels; ++ch) {
            const auto& cc = FheManager::getInstance().getRnsContext(ch);
            const auto& sk = FheManager::getInstance().getRnsKeyPair(ch).secretKey;
            std::vector<int64_t> r_residues(slot_count);
            for (size_t s = 0; s < slot_count; ++s) {
                r_residues[s] = static_cast<int64_t>(raw_r[s] % moduli[ch]);
            }
            Plaintext pt_r = cc->MakePackedPlaintext(r_residues);
            auto ct_masked = cc->EvalSub((*cts_for_party_b)[ch], pt_r);
            { std::ostringstream oss; Serial::Serialize(ct_masked, oss, SerType::BINARY); ct_masked_strs[ch] = oss.str(); }
            auto ct_partial_B = cc->MultipartyDecryptLead({ct_masked}, sk).at(0);
            { std::ostringstream oss; Serial::Serialize(ct_partial_B, oss, SerType::BINARY); partial_strs[ch] = oss.str(); }
        }

        if (masked_ct_serialized && !ct_masked_strs.empty()) {
            *masked_ct_serialized = ct_masked_strs[0];
        }

        // Phase 2: Sequential send (preserves protocol order).
        for (size_t ch = 0; ch < num_channels; ++ch) {
            mpc_network_io->sendString(ct_masked_strs[ch]);
            mpc_network_io->sendString(partial_strs[ch]);
        }
        std::vector<int64_t> raw_r_signed(slot_count);
        for (size_t s = 0; s < slot_count; ++s) {
            raw_r_signed[s] = static_cast<int64_t>(raw_r[s]);
        }
        if (FLAGS_debug) std::cout << "[Party B] Step4: Val_B = raw R per slot held for MPC." << std::endl;
        return {raw_r_signed, std::vector<int64_t>{}};
    }

    // Step 4: C receives Enc(M-R) per channel, decrypts, CRT-combines to get Val_C = (M-R) mod P_total.
    if (party == 3) {
        // Phase 1: Sequential receive (network-bound).
        std::vector<std::string> ct_masked_strs(num_channels);
        std::vector<std::string> share_strs(num_channels);
        for (size_t ch = 0; ch < num_channels; ++ch) {
            ct_masked_strs[ch] = mpc_network_io->recvString();
            share_strs[ch] = mpc_network_io->recvString();
        }

        // Phase 2: Parallel deserialize + decrypt + decode (each channel independent).
        std::vector<std::vector<int64_t>> per_channel_mr(num_channels);
        #pragma omp parallel for schedule(static)
        for (size_t ch = 0; ch < num_channels; ++ch) {
            Ciphertext<DCRTPoly> ct_masked;
            { std::istringstream iss(ct_masked_strs[ch]); Serial::Deserialize(ct_masked, iss, SerType::BINARY); }
            Ciphertext<DCRTPoly> ct_partial_B;
            { std::istringstream iss(share_strs[ch]); Serial::Deserialize(ct_partial_B, iss, SerType::BINARY); }
            const auto& cc = FheManager::getInstance().getRnsContext(ch);
            const auto& sk = FheManager::getInstance().getRnsKeyPair(ch).secretKey;
            auto ct_partial_C = cc->MultipartyDecryptMain({ct_masked}, sk).at(0);
            NativePoly result_poly;
            cc->GetScheme()->MultipartyDecryptFusion({ct_partial_B, ct_partial_C}, &result_poly);
            auto vals = DecodePackedValuesFromNativePoly(result_poly, cc);
            if (slot_count > 0 && vals.size() > slot_count) vals.resize(slot_count);
            per_channel_mr[ch] = std::move(vals);
        }
        std::vector<int64_t> m_minus_r(slot_count);
        for (size_t s = 0; s < slot_count; ++s) {
            std::vector<uint64_t> residues(num_channels);
            for (size_t ch = 0; ch < num_channels; ++ch) {
                int64_t v = (s < per_channel_mr[ch].size()) ? per_channel_mr[ch][s] : 0;
                uint64_t m = moduli[ch];
                residues[ch] = static_cast<uint64_t>(v < 0 ? (v + static_cast<int64_t>(m)) : v) % m;
            }
            m_minus_r[s] = CrtCombine(residues, moduli);
        }
        if (FLAGS_debug) {
            std::cout << "[Party C] Step4: Val_C = (M-R) mod P_total (first 5): ";
            for (size_t i = 0; i < std::min(size_t(5), m_minus_r.size()); ++i) {
                std::cout << m_minus_r[i] << " ";
            }
            std::cout << std::endl;
        }
        return {std::vector<int64_t>{}, m_minus_r};
    }

    throw std::runtime_error("DecryptWithNoiseMultiChannel: Invalid party");
}

} // namespace vaultdb
