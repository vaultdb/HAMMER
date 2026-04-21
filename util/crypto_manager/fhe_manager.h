#ifndef _FHE_MANAGER_
#define _FHE_MANAGER_

#include <stdint.h>
#include <common/defs.h>
#include <util/crypto_manager/crypto_manager.h>
#include <util/system_configuration.h>
#include <query_table/field/field_type.h>
#include <openfhe/pke/openfhe.h>
#include <query_table/columnar/fhe_column_type.h>  // Includes FheSchemeType
#include <array>
#include <chrono>
#include <cmath>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace lbcrypto;
namespace vaultdb {
    enum class CalType {
        BASIC = 0,
        MUL,
        DIV,
        MOD,
        AND,
        OR,
        XOR,
        COMPARE,
        ROTATE,
        UNKNOWN
    };

        class FheManager : public CryptoManager {
        public:
            static FheManager& getInstance() {
                static FheManager instance;
                return instance;
            }

            FheManager(const FheManager&) = delete;
            FheManager& operator=(const FheManager&) = delete;
            FheManager(FheManager&&) = delete;
            FheManager& operator=(FheManager&&) = delete;

            // ============================================================
            // BFV Parameters (single scheme; no CKKS)
            // ============================================================
            uint64_t bfv_plaintext_modulus_ = 65537;
            uint32_t bfv_mult_depth_        = 13;
            uint32_t bfv_ring_dim_          = 32768;  // OpenFHE 1.4+ requires 65536 for HEStd_128; 32768 rejected
            SecurityLevel bfv_security_level_ = HEStd_128_classic;
            uint32_t bfv_batch_size_        = bfv_ring_dim_ / 2;

            // ============================================================
            // RNS Moduli for 64-bit coverage (NTT-friendly: p ≡ 1 (mod 65536))
            // Product ≈ 2^71; N=65536. Levels: 1→16b, 2→34b, 3→53b, 4→71b.
            // ============================================================
            std::vector<uint64_t> rns_moduli_;
            std::vector<CryptoContext<DCRTPoly>> rns_contexts_;
            std::vector<KeyPair<DCRTPoly>> rns_key_pairs_;
            // Quantization
            uint32_t quant_precision_   = 16;
            uint32_t quant_base_bits_   = 8;
            double scale_factor_        = std::pow(2.0, 40);
            const int quantization_threshold_ = (1 << (quant_precision_ - 1)) - 1;

            QuantizationParams getDefaultQuantizationParams() const {
                QuantizationParams params;
                params.targetPrecisionBits = static_cast<uint32_t>(std::log2(scale_factor_));
                params.B_g = quant_base_bits_;
                params.scale = scale_factor_;
                params.ckksLevel = 0;
                params.simdSlots = static_cast<unsigned int>(bfv_batch_size_);
                return params;
            }
            
            // BFV accessors
            uint64_t getBFVPlaintextModulus() const { return bfv_plaintext_modulus_; }
            uint32_t getBFVMultDepth() const { return bfv_mult_depth_; }
            uint32_t getBFVRingDim() const { return bfv_ring_dim_; }
            uint32_t getBFVBatchSize() const { return bfv_batch_size_; }
            uint32_t getBFVComparisonBatchSize() const { return bfv_batch_size_; }
            SecurityLevel getBFVSecurityLevel() const { return bfv_security_level_; }
            size_t getChunkPackingSize() const { return bfv_batch_size_; }

            // RNS accessors (64-bit coverage: 4 moduli)
            size_t getRnsCount() const { return rns_moduli_.size(); }
            const std::vector<uint64_t>& getRnsModuli() const { return rns_moduli_; }
            const CryptoContext<DCRTPoly>& getRnsContext(size_t idx) const {
                if (idx >= rns_contexts_.size()) throw std::runtime_error("FheManager::getRnsContext: index out of range");
                return rns_contexts_[idx];
            }
            const KeyPair<DCRTPoly>& getRnsKeyPair(size_t idx) const {
                if (idx >= rns_key_pairs_.size()) throw std::runtime_error("FheManager::getRnsKeyPair: index out of range");
                return rns_key_pairs_[idx];
            }

            /// RNS count used for encryption/aggregation (fixed; always full moduli set).
            size_t getEffectiveRnsCount(double /* max_val */, uint64_t /* row_count */) const {
                return getRnsCount();
            }

            size_t getPackingSizeForScheme(FheSchemeType scheme) const {
                switch (scheme) {
                    case FheSchemeType::BFV:
                    case FheSchemeType::BGV:
                    case FheSchemeType::CKKS:
                        return bfv_ring_dim_;
                    case FheSchemeType::TFHE:
                        return 1;
                    default:
                        return bfv_ring_dim_;
                }
            }

            /// FHE has no and-gate concept; returns 0 for compatibility with Operator timing.
            size_t andGateCount() const override { return 0; }
            size_t getCommCost() const override { return 0L; }

            void flush() override {}

            void initializeCryptoContext() {
                // Step 1: 3-prime RNS for ~60-bit range (M = R + (M-R) in MPC).
                // For ring_dim=65536: m=131072, need p ≡ 1 (mod 131072). 65537 fails: (65537-1)/131072 ∉ Z.
                // 64-bit plaintext space: 1179649*2752513*8519681 ≈ 2^64.6 (NTT-friendly: p≡1 mod 131072).
                // Note: 9043969=11*822179 is composite; use 8519681=65*131072+1 instead.
                rns_moduli_ = {1179649, 2752513, 8519681};
                rns_contexts_.clear();
                rns_key_pairs_.clear();

                for (uint64_t mod : rns_moduli_) {
                    CCParams<CryptoContextBFVRNS> params;
                    params.SetSecurityLevel(bfv_security_level_);
                    params.SetPlaintextModulus(mod);
                    params.SetMultiplicativeDepth(bfv_mult_depth_);
                    params.SetRingDim(bfv_ring_dim_);
                    params.SetBatchSize(bfv_batch_size_);
                    params.SetSecretKeyDist(UNIFORM_TERNARY);
                    params.SetKeySwitchTechnique(HYBRID);
                    params.SetMaxRelinSkDeg(2);

                    auto cc = GenCryptoContext(params);
                    if (!cc) {
                        throw std::runtime_error("FATAL: GenCryptoContext failed for modulus " + std::to_string(mod));
                    }
                    rns_contexts_.push_back(cc);
                }

                bfv_crypto_context_ = rns_contexts_.empty() ? CryptoContext<DCRTPoly>() : rns_contexts_[0];
                bfv_plaintext_modulus_ = rns_moduli_.empty() ? 65537 : rns_moduli_[0];
                std::cout << "[FheManager] Initialized " << rns_contexts_.size() << " RNS contexts for full 64-bit support." << std::endl;
            }

            // New overload: accepts ring_dim and mult_depth from QueryExecutionPlan
            void initializeForQuery(const std::string& query_name,
                                    uint32_t ring_dim, uint32_t mult_depth) {
                bfv_ring_dim_   = ring_dim;
                bfv_mult_depth_ = mult_depth;
                bfv_batch_size_ = bfv_ring_dim_ / 2;
                std::cout << "[FheManager] query=" << query_name
                          << " ring_dim=" << bfv_ring_dim_
                          << " mult_depth=" << bfv_mult_depth_
                          << " (from QueryExecutionPlan)"
                          << std::endl;
                initializeCryptoContext();
            }

            // Legacy fallback: hardcoded ring_dim selection (used when no query plan available)
            void initializeForQuery(const std::string& query_name) {
                static const std::unordered_set<std::string> kLargeQueries = {"q6", "q12"};
                bool needs_large = kLargeQueries.count(query_name) > 0;
                bfv_ring_dim_   = needs_large ? 65536 : 32768;
                bfv_mult_depth_ = 13;
                bfv_batch_size_ = bfv_ring_dim_ / 2;
                std::cout << "[FheManager] query=" << query_name
                          << " ring_dim=" << bfv_ring_dim_
                          << " mult_depth=" << bfv_mult_depth_
                          << " (" << (needs_large ? "large: rotation noise" : "small: fast path") << ")"
                          << std::endl;
                initializeCryptoContext();
            }

            virtual void feed(Bit* labels, int party, const bool* b, int bit_cnt) override {
                throw std::runtime_error("feed not implemented for FheManager");
            }

            virtual void reveal(bool* dst, const int& party, Bit* src, const int& bit_cnt) override {
                throw std::runtime_error("reveal not implemented for FheManager");
            }

            virtual string revealToString(const emp::Integer& i, const int& party = PUBLIC) const override {
                throw std::runtime_error("revealToString not implemented for FheManager");
            }

            virtual int sendingParty() const override {
                throw std::runtime_error("sendingParty not implemented for FheManager");
            }

            virtual QueryTable<Bit>* secretShare(const QueryTable<bool>* src) override {
                throw std::runtime_error("secretShare not implemented for FheManager");
            }

            virtual void sendPublic(const int& to_send) override {
                throw std::runtime_error("sendPublic not implemented for FheManager");
            }

            virtual int recvPublic() override {
                throw std::runtime_error("recvPublic not implemented for FheManager");
            }

            virtual void setDelta(const block& delta) override {
                throw std::runtime_error("setDelta not implemented for FheManager");
            }

            size_t getTableCardinality(const int& local_cardinality) override {
                return local_cardinality;
            }

            // BFV context and keys
            const CryptoContext<DCRTPoly>& getBFVCryptoContext() const { return bfv_crypto_context_; }
            const KeyPair<DCRTPoly>& getBFVKeyPair() const { return bfv_key_pair_; }

            PublicKey<DCRTPoly> getBFVPublicKey() const {
                if (!bfv_key_pair_.publicKey) {
                    if (decrypt_only_mode_) return PublicKey<DCRTPoly>();  // Party C: blank pk (decrypt-only)
                    throw std::runtime_error("BFV public key is null in FheManager.");
                }
                return bfv_key_pair_.publicKey;
            }

            /// Party C only: allow null public key (getBFVPublicKey returns default; pk never used for encrypt).
            void setDecryptOnlyMode(bool v) { decrypt_only_mode_ = v; }

            PrivateKey<DCRTPoly> getBFVSecretKey() const {
                if (!bfv_key_pair_.secretKey) {
                    return PrivateKey<DCRTPoly>();
                }
                return bfv_key_pair_.secretKey;
            }

            // Aliases (BFV only)
            const CryptoContext<DCRTPoly>& getIntegerCryptoContext() const { return bfv_crypto_context_; }
            PublicKey<DCRTPoly> getIntegerPublicKey() const { return getBFVPublicKey(); }
            PrivateKey<DCRTPoly> getIntegerSecretKey() const { return getBFVSecretKey(); }

            const CryptoContext<DCRTPoly>& getComparisonCryptoContext() const { return bfv_crypto_context_; }
            PublicKey<DCRTPoly> getComparisonPublicKey() const { return getBFVPublicKey(); }
            PrivateKey<DCRTPoly> getComparisonSecretKey() const { return getBFVSecretKey(); }

            // Backward compatibility: Real/CKKS aliases (now BFV-only; CKKS removed)
            const CryptoContext<DCRTPoly>& getRealCryptoContext() const { return bfv_crypto_context_; }
            const KeyPair<DCRTPoly>& getRealKeyPair() const { return bfv_key_pair_; }
            PublicKey<DCRTPoly> getRealPublicKey() const { return getBFVPublicKey(); }
            PrivateKey<DCRTPoly> getRealSecretKey() const { return getBFVSecretKey(); }

            void setBFVCryptoContext(const CryptoContext<DCRTPoly>& cc) {
                bfv_crypto_context_ = cc;
                bfv_key_pair_ = KeyPair<DCRTPoly>();
                rns_contexts_.clear();
                rns_key_pairs_.clear();
                rns_moduli_.clear();
                clearCaches();
            }

            void setBFVPublicKey(const PublicKey<DCRTPoly>& pk) {
                bfv_key_pair_ = KeyPair<DCRTPoly>();
                bfv_key_pair_.publicKey = pk;
                clearCaches();
            }

            /// Set RNS contexts and key shares received from Party A (B/C only). Does not clear
            /// bfv_crypto_context_; use after setBFVCryptoContext/setBFVPublicKey so filter uses
            /// first context and aggregation can use all channels (getRnsCount() > 1).
            void setRnsFromPartyA(
                const CryptoContext<DCRTPoly>& first_cc,
                const PublicKey<DCRTPoly>& first_pk,
                const PrivateKey<DCRTPoly>& first_sk_share,
                const std::vector<CryptoContext<DCRTPoly>>& extra_contexts,
                const std::vector<PublicKey<DCRTPoly>>& extra_pks,
                const std::vector<PrivateKey<DCRTPoly>>& extra_sk_shares) {
                if (extra_pks.size() != extra_contexts.size() || extra_sk_shares.size() != extra_contexts.size()) {
                    throw std::runtime_error("setRnsFromPartyA: extra_contexts/pks/sk_shares size mismatch");
                }
                rns_contexts_.clear();
                rns_moduli_.clear();
                rns_key_pairs_.clear();
                rns_contexts_.push_back(first_cc);
                rns_moduli_.push_back(first_cc->GetCryptoParameters()->GetPlaintextModulus());
                KeyPair<DCRTPoly> kp0;
                kp0.publicKey = first_pk;
                kp0.secretKey = first_sk_share;
                rns_key_pairs_.push_back(kp0);
                for (size_t i = 0; i < extra_contexts.size(); ++i) {
                    rns_contexts_.push_back(extra_contexts[i]);
                    rns_moduli_.push_back(extra_contexts[i]->GetCryptoParameters()->GetPlaintextModulus());
                    KeyPair<DCRTPoly> kp;
                    kp.publicKey = extra_pks[i];
                    kp.secretKey = extra_sk_shares[i];
                    rns_key_pairs_.push_back(kp);
                }
                std::cout << "[FheManager] setRnsFromPartyA: " << rns_contexts_.size() << " RNS channels (64-bit aggregation)." << std::endl;
                printRnsContextMetrics("setRnsFromPartyA");
            }

            /// Party C only: set RNS contexts and secret key shares for partial decryption. No public keys
            /// (C does not encrypt or homomorphic op; only MultipartyDecryptMain uses cc + sk_share).
            void setRnsFromPartyADecryptOnly(
                const CryptoContext<DCRTPoly>& first_cc,
                const PrivateKey<DCRTPoly>& first_sk_share,
                const std::vector<CryptoContext<DCRTPoly>>& extra_contexts,
                const std::vector<PrivateKey<DCRTPoly>>& extra_sk_shares) {
                if (extra_sk_shares.size() != extra_contexts.size()) {
                    throw std::runtime_error("setRnsFromPartyADecryptOnly: extra_contexts/extra_sk_shares size mismatch");
                }
                rns_contexts_.clear();
                rns_moduli_.clear();
                rns_key_pairs_.clear();
                rns_contexts_.push_back(first_cc);
                rns_moduli_.push_back(first_cc->GetCryptoParameters()->GetPlaintextModulus());
                KeyPair<DCRTPoly> kp0;
                kp0.publicKey = PublicKey<DCRTPoly>();  // unused on C
                kp0.secretKey = first_sk_share;
                rns_key_pairs_.push_back(kp0);
                for (size_t i = 0; i < extra_contexts.size(); ++i) {
                    rns_contexts_.push_back(extra_contexts[i]);
                    rns_moduli_.push_back(extra_contexts[i]->GetCryptoParameters()->GetPlaintextModulus());
                    KeyPair<DCRTPoly> kp;
                    kp.publicKey = PublicKey<DCRTPoly>();
                    kp.secretKey = extra_sk_shares[i];
                    rns_key_pairs_.push_back(kp);
                }
                std::cout << "[FheManager] setRnsFromPartyADecryptOnly: " << rns_contexts_.size() << " RNS channels (Party C decrypt only)." << std::endl;
                printRnsContextMetrics("setRnsFromPartyADecryptOnly");
            }

            void resetBFVContext() {
                decrypt_only_mode_ = false;
                bfv_crypto_context_ = CryptoContext<DCRTPoly>();
                bfv_key_pair_ = KeyPair<DCRTPoly>();
                rns_contexts_.clear();
                rns_key_pairs_.clear();
                rns_moduli_.clear();
                clearCaches();
            }

        /// inv2 = (p+1)/2 mod p, for decode GT = R*(R-1)*inv2
        Plaintext getInv2Plaintext(size_t pack_slots) const {
            auto it = inv2_plain_cache_.find(pack_slots);
            if (it != inv2_plain_cache_.end()) return it->second;
            if (!bfv_crypto_context_) {
                throw std::runtime_error("FheManager::getInv2Plaintext: crypto context not set");
            }
            uint64_t p = bfv_crypto_context_->GetCryptoParameters()->GetPlaintextModulus();
            int64_t inv2 = static_cast<int64_t>((p + 1) / 2);  // (p+1)/2 mod p
            std::vector<int64_t> vec(pack_slots, inv2);
            Plaintext pt = bfv_crypto_context_->MakePackedPlaintext(vec);
            inv2_plain_cache_.emplace(pack_slots, pt);
            return pt;
        }

        /// two = 2, for decode EQ = R*(2-R) (or EvalSub(ones, R*(R-2)))
        Plaintext getTwoPlaintext(size_t pack_slots) const {
            auto it = two_plain_cache_.find(pack_slots);
            if (it != two_plain_cache_.end()) return it->second;
            if (!bfv_crypto_context_) {
                throw std::runtime_error("FheManager::getTwoPlaintext: crypto context not set");
            }
            std::vector<int64_t> vec(pack_slots, 2);
            Plaintext pt = bfv_crypto_context_->MakePackedPlaintext(vec);
            two_plain_cache_.emplace(pack_slots, pt);
            return pt;
        }

        /// Cached encrypted all-ones vector for NOT/OR operations. Avoids repeated Encrypt per run.
        Ciphertext<DCRTPoly> getOnesCipher(size_t pack_slots) const {
            auto it = ones_cipher_cache_.find(pack_slots);
            if (it != ones_cipher_cache_.end()) {
                return it->second;
            }
            if (!bfv_crypto_context_ || !bfv_key_pair_.publicKey) {
                throw std::runtime_error("FheManager::getOnesCipher: crypto context or public key not set");
            }
            std::vector<int64_t> ones_vec(pack_slots, 1);
            Plaintext ones_plain = bfv_crypto_context_->MakePackedPlaintext(ones_vec);
            Ciphertext<DCRTPoly> enc = bfv_crypto_context_->Encrypt(bfv_key_pair_.publicKey, ones_plain);
            ones_cipher_cache_[pack_slots] = enc;
            return enc;
        }

        /// Cached encrypted all-zeros vector for BSGS limbs with no non-zero coeffs. Avoids repeated Encrypt.
        Ciphertext<DCRTPoly> getZeroCipher(size_t pack_slots) const {
            auto it = zero_cipher_cache_.find(pack_slots);
            if (it != zero_cipher_cache_.end()) {
                return it->second;
            }
            if (!bfv_crypto_context_ || !bfv_key_pair_.publicKey) {
                throw std::runtime_error("FheManager::getZeroCipher: crypto context or public key not set");
            }
            std::vector<int64_t> zeros_vec(pack_slots, 0);
            Plaintext zeros_plain = bfv_crypto_context_->MakePackedPlaintext(zeros_vec);
            Ciphertext<DCRTPoly> enc = bfv_crypto_context_->Encrypt(bfv_key_pair_.publicKey, zeros_plain);
            zero_cipher_cache_[pack_slots] = enc;
            return enc;
        }

        /// Cached encrypted all-twos (value 2) for Phase C decode: EQ = R*(2-R).
        Ciphertext<DCRTPoly> getTwoCipher(size_t pack_slots) const {
            auto it = two_cipher_cache_.find(pack_slots);
            if (it != two_cipher_cache_.end()) return it->second;
            if (!bfv_crypto_context_ || !bfv_key_pair_.publicKey) {
                throw std::runtime_error("FheManager::getTwoCipher: crypto context or public key not set");
            }
            std::vector<int64_t> two_vec(pack_slots, 2);
            Plaintext two_plain = bfv_crypto_context_->MakePackedPlaintext(two_vec);
            Ciphertext<DCRTPoly> enc = bfv_crypto_context_->Encrypt(bfv_key_pair_.publicKey, two_plain);
            two_cipher_cache_[pack_slots] = enc;
            return enc;
        }

        void generateKeys() {
            using clock = std::chrono::high_resolution_clock;
            auto keygen_start = clock::now();
            rns_key_pairs_.clear();
            if (rns_contexts_.empty()) {
                throw std::runtime_error("FheManager::generateKeys: RNS contexts not initialized. Call initializeCryptoContext first.");
            }

            std::vector<int32_t> bfv_rotation_indices;
            for (size_t step = 1; step < bfv_batch_size_; step *= 2) {
                bfv_rotation_indices.push_back(static_cast<int32_t>(step));
            }
            const uint32_t max_packing_power = bfv_batch_size_;
            for (uint32_t power = 1; power <= max_packing_power; power *= 2) {
                bfv_rotation_indices.push_back(-static_cast<int32_t>(power));
            }

            for (size_t i = 0; i < rns_contexts_.size(); ++i) {
                auto ch_start = clock::now();
                auto& cc = rns_contexts_[i];
                cc->Enable(PKE);
                cc->Enable(KEYSWITCH);
                cc->Enable(LEVELEDSHE);
                cc->Enable(ADVANCEDSHE);

                auto kp = cc->KeyGen();
                if (!kp.secretKey) {
                    throw std::runtime_error("BFV secret key generation failed for RNS index " + std::to_string(i));
                }
                cc->EvalMultKeyGen(kp.secretKey);
                cc->EvalRotateKeyGen(kp.secretKey, bfv_rotation_indices);
                rns_key_pairs_.push_back(kp);
                auto ch_end = clock::now();
                double ch_ms = std::chrono::duration_cast<std::chrono::microseconds>(ch_end - ch_start).count() / 1000.0;
                std::cout << "[FheManager][Timing] KeyGen channel " << i << ": " << ch_ms << " ms" << std::endl;
            }

            bfv_key_pair_ = rns_key_pairs_[0];
            clearCaches();
            auto keygen_end = clock::now();
            double total_ms = std::chrono::duration_cast<std::chrono::microseconds>(keygen_end - keygen_start).count() / 1000.0;
            std::cout << "[FheManager][Timing] KeyGen total: " << total_ms << " ms" << std::endl;
            std::cout << "[FheManager] BFV keys generated for " << rns_key_pairs_.size() << " RNS contexts." << std::endl;
            printRnsContextMetrics("generateKeys");
        }

    private:
        void clearCaches() {
            ones_cipher_cache_.clear();
            zero_cipher_cache_.clear();
            inv2_plain_cache_.clear();
            two_plain_cache_.clear();
            two_cipher_cache_.clear();
        }

        static uint32_t bitLengthU64(uint64_t x) {
            if (x == 0) return 0;
            uint32_t bits = 0;
            while (x > 0) {
                ++bits;
                x >>= 1;
            }
            return bits;
        }

        void printRnsContextMetrics(const std::string& stage) const {
            std::cout << "[FheManager][Debug][" << stage << "] ===== RNS Context Metrics =====" << std::endl;
            for (size_t idx = 0; idx < rns_contexts_.size(); ++idx) {
                const auto& cc = rns_contexts_[idx];
                if (!cc) {
                    std::cout << "[FheManager][Debug][" << stage << "] ch=" << idx << " context=null" << std::endl;
                    continue;
                }

                uint32_t ring_dim = cc->GetRingDimension();
                uint32_t batch_size = bfv_batch_size_;
                auto crypto_params = cc->GetCryptoParameters();
                uint64_t t = crypto_params->GetPlaintextModulus();

                std::vector<uint64_t> qi_vals;
                std::vector<uint32_t> qi_bits;
                double log2Q = 0.0;
                size_t L = 0;
                if (crypto_params && crypto_params->GetElementParams()) {
                    const auto& tower_params = crypto_params->GetElementParams()->GetParams();
                    L = tower_params.size();
                    qi_vals.reserve(L);
                    qi_bits.reserve(L);
                    for (const auto& tp : tower_params) {
                        uint64_t qi = tp->GetModulus().ConvertToInt();
                        uint32_t bits = bitLengthU64(qi);
                        qi_vals.push_back(qi);
                        qi_bits.push_back(bits);
                        log2Q += std::log2(static_cast<double>(qi));
                    }
                }

                std::ostringstream qbits_ss;
                std::ostringstream qvals_ss;
                std::ostringstream t_towers_ss;
                qbits_ss << "[";
                qvals_ss << "[";
                t_towers_ss << "[";
                for (size_t i = 0; i < qi_bits.size(); ++i) {
                    if (i) {
                        qbits_ss << ", ";
                        qvals_ss << ", ";
                        t_towers_ss << ", ";
                    }
                    qbits_ss << qi_bits[i];
                    qvals_ss << qi_vals[i];
                    t_towers_ss << t;
                }
                qbits_ss << "]";
                qvals_ss << "]";
                t_towers_ss << "]";

                std::cout << "[FheManager][Debug][" << stage << "] ch=" << idx
                          << " ring_dim=" << ring_dim
                          << " batch_size=" << batch_size
                          << " L=" << L
                          << " log2Q~" << log2Q
                          << " t=" << t
                          << " t_bits=" << bitLengthU64(t)
                          << " qi_bits=" << qbits_ss.str()
                          << " qi=" << qvals_ss.str()
                          << " t_towers=" << t_towers_ss.str()
                          << std::endl;
            }
            std::cout << "[FheManager][Debug][" << stage << "] =================================" << std::endl;
        }

        FheManager() {
            SystemConfiguration& s = SystemConfiguration::getInstance();
            s.crypto_mode_ = CryptoMode::OPENFHE;
            s.party_ = 10087;
            initializeCryptoContext();
            // Keys: Party A only calls generateKeys(). B/C receive from A.
        }

        ~FheManager() override = default;

        CryptoContext<DCRTPoly> bfv_crypto_context_;
        KeyPair<DCRTPoly> bfv_key_pair_;
        bool decrypt_only_mode_ = false;  // Party C: blank public key allowed (decrypt-only)
        mutable std::unordered_map<size_t, Ciphertext<DCRTPoly>> ones_cipher_cache_;
        mutable std::unordered_map<size_t, Ciphertext<DCRTPoly>> zero_cipher_cache_;
        mutable std::unordered_map<size_t, Plaintext> inv2_plain_cache_;
        mutable std::unordered_map<size_t, Plaintext> two_plain_cache_;
        mutable std::unordered_map<size_t, Ciphertext<DCRTPoly>> two_cipher_cache_;
    };

}

#endif
