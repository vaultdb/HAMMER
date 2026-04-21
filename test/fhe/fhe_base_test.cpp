#include "fhe_base_test.h"
#include <util/logger.h>
#include <util/data_utilities.h>
#include <util/system_configuration.h>
#include <util/dictionary_manager.h>
#include <util/utilities.h>
#include <boost/algorithm/string.hpp>
#include <util/fhe/fhe_helpers.h>
#include <util/fhe/fhe_query_plan.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <iostream>
#include "openfhe.h"
#include <openfhe/core/utils/serial.h>
#include <openfhe/pke/key/key-ser.h>
#include <openfhe/pke/ciphertext-ser.h>
#include <openfhe/pke/cryptocontext-ser.h>
// BFV and CKKS scheme serialization headers (required for polymorphic type registration)
#include <openfhe/pke/scheme/bfvrns/bfvrns-ser.h>
#include <openfhe/pke/scheme/ckksrns/ckksrns-ser.h>
#include <chrono>
#include <sstream>
#include <thread>
#include <query_table/columnar/fhe_column_table.h>
#include <query_table/columnar/fhe_column.h>
#include <query_table/columnar/fhe_column_chunk.h>
#include <query_table/columnar/fhe_column_type.h>
#include <query_table/columnar/column_table_base.h>
#include <query_table/columnar/column_base.h>
#include <cmath>

using namespace vaultdb;
using namespace Logging;

// Flags defined in util/google_test_flags.cpp (libvaultdb-emp), DECLAREd in util/google_test_flags.h

const std::string FheBaseTest::empty_db_ = "tpch_empty";
const CryptoMode FheBaseTest::crypto_mode_ = CryptoMode::OPENFHE;
std::string FheBaseTest::db_name_ = "";
const StorageModel FheBaseTest::storage_model_ = StorageModel::COLUMN_STORE;

// Now references the singleton
FheManager* FheBaseTest::manager_ = nullptr;
const CryptoContext<DCRTPoly>* FheBaseTest::real_crypto_context_ = nullptr;
const KeyPair<DCRTPoly>* FheBaseTest::real_key_pair_ = nullptr;

// Helper function to split Secret Key into two additive shares
// Implements Trusted Dealer model: Client splits SK into SK_B + SK_C (mod q)
namespace {
    std::pair<lbcrypto::PrivateKey<lbcrypto::DCRTPoly>, lbcrypto::PrivateKey<lbcrypto::DCRTPoly>> 
    SplitSecretKey(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> originalKey, lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc) {
        if (!originalKey) {
            throw std::runtime_error("SplitSecretKey: Original key is null");
        }
        if (!cc) {
            throw std::runtime_error("SplitSecretKey: CryptoContext is null");
        }

        // 1. Get the underlying DCRTPoly element from the original secret key (s)
        const lbcrypto::DCRTPoly& s = originalKey->GetPrivateElement();
        
        // 2. Get parameters for generating random mask (ciphertext modulus q etc.)
        auto params = cc->GetElementParams();
        
        // 3. Generate Share B: Uniform Random Polynomial in R_q
        // Use DiscreteUniformGeneratorImpl to generate a random polynomial matching the parameters.
        // Secret Keys are typically stored in EVALUATION format (NTT state) for multiplication efficiency,
        // so we generate the random mask in the same format to avoid errors during subtraction.
        using DugType = typename lbcrypto::DCRTPoly::DugType;
        DugType dug;
        lbcrypto::DCRTPoly share_B_poly(dug, params, Format::EVALUATION);
        
        // 4. Compute Share C: s - Share B (mod q)
        // DCRTPoly subtraction operator (-) automatically handles modular arithmetic.
        lbcrypto::DCRTPoly share_C_poly = s - share_B_poly;
        
        // 5. Create PrivateKey objects from DCRTPoly shares
        auto share_B = std::make_shared<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>(cc);
        share_B->SetPrivateElement(share_B_poly);
        
        auto share_C = std::make_shared<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>>(cc);
        share_C->SetPrivateElement(share_C_poly);
        
        return {share_B, share_C};
    }
}

void FheBaseTest::SetUpTestSuite() {
    SystemConfiguration &s = SystemConfiguration::getInstance();
    s.crypto_mode_ = CryptoMode::OPENFHE;
    s.setStorageModel(storage_model_);

    Logger* log = get_log();

    // Get the singleton instance
    manager_ = &FheManager::getInstance();

    s.setEmptyDbName(empty_db_);
    s.crypto_manager_ = manager_;  // For compatibility with code still using SystemConfiguration

    std::string settings = Utilities::getTestParameters();
    log->write(settings, Level::INFO);

    real_crypto_context_ = &(manager_->getRealCryptoContext());
    real_key_pair_ = &(manager_->getRealKeyPair());

    // Set database name from flag if provided; fallback to previous default
    if (FLAGS_unioned_db.empty()) {
        db_name_ = "tpch_unioned_1500";
    } else {
        db_name_ = FLAGS_unioned_db;
    }
    get_log()->write("[FheBaseTest] Using database: " + db_name_, Level::INFO);
}

void FheBaseTest::SetUp() {
    // 3-party setup: Party A (client) generates keys and splits secret key, Party B and C (servers) receive keys
    // Or single-party mode: no network, just local key gen (for fhe_filter_test etc)
    Logger* log = get_log();

    // Use --party when 1/2/3 (FHE 3-party); else --fhe_party so --party=1 (Alice) doesn't override explicit --fhe_party=2
    int party = (FLAGS_fhe_party > 0) ? FLAGS_fhe_party : 1;
    if (FLAGS_party >= 1 && FLAGS_party <= 3) {
        party = FLAGS_party;
    }
    int port_B = (FLAGS_fhe_port > 0) ? FLAGS_fhe_port : 8765;
    int port_C = (FLAGS_fhe_charlie_port > 0) ? FLAGS_fhe_charlie_port : 8766;
    std::string bob_host = FLAGS_fhe_bob_host.empty() ? "127.0.0.1" : FLAGS_fhe_bob_host;
    std::string charlie_host = FLAGS_fhe_charlie_host.empty() ? "127.0.0.1" : FLAGS_fhe_charlie_host;

    SystemConfiguration &s = SystemConfiguration::getInstance();
    s.party_ = party;

    // Joint optimizer: extract query name → build QueryExecutionPlan → set ring_dim/mult_depth
    {
        const auto* test_info = ::testing::UnitTest::GetInstance()->current_test_info();
        if (test_info) {
            std::string tname = test_info->name();
            std::string query_name;
            auto qpos = tname.rfind("_q");
            if (qpos != std::string::npos) {
                size_t start = qpos + 1;
                size_t end = start + 1;
                while (end < tname.size() && std::isdigit(tname[end])) end++;
                query_name = tname.substr(start, end - start);
            }
            if (!query_name.empty()) {
                std::string plan_file;
                if (!FLAGS_fhe_plan_path_override.empty()) {
                    plan_file = FLAGS_fhe_plan_path_override;
                    std::cout << "[QueryPlan] PLAN_PATH OVERRIDE: " << plan_file << std::endl;
                } else {
                    plan_file = Utilities::getCurrentWorkingDirectory()
                              + "/conf/plans/fhe/" + query_name + ".json";
                }
                const auto& sp = vaultdb::globalServerProfile();
                auto plan = vaultdb::buildQueryPlan(query_name, plan_file, sp);

                // --fhe_force_baseline: override with conservative N=65536, m=15
                if (FLAGS_fhe_force_baseline) {
                    plan.ring_dim = 65536;
                    plan.mult_depth = 15;
                    plan.used_empirical_depth = false;
                    plan.ct_size_bytes = vaultdb::ctBytes(65536, 15);
                    plan.working_set_filter_bytes = static_cast<size_t>(
                        vaultdb::workingSetFilter(65536, 15, 3.0));
                    plan.working_set_agg_bytes = static_cast<size_t>(
                        vaultdb::workingSetAgg(65536, 15, 2.0));
                    if (sp.is_loaded && sp.l3_cache_bytes > 0) {
                        double l3 = static_cast<double>(sp.l3_cache_bytes);
                        plan.rho_filter = static_cast<double>(plan.working_set_filter_bytes) / l3;
                        plan.rho_agg = static_cast<double>(plan.working_set_agg_bytes) / l3;
                        plan.fits_l3 = (plan.rho_filter <= 1.05);
                    }
                    std::cout << "[QueryPlan] BASELINE OVERRIDE: ring_dim=65536 mult_depth=15"
                              << std::endl;
                }

                // --fhe_force_ring_dim / --fhe_force_mult_depth: selective overrides
                if (FLAGS_fhe_force_ring_dim > 0) {
                    plan.ring_dim = FLAGS_fhe_force_ring_dim;
                    std::cout << "[QueryPlan] RING_DIM OVERRIDE: " << plan.ring_dim << std::endl;
                }
                if (FLAGS_fhe_force_mult_depth > 0) {
                    plan.mult_depth = FLAGS_fhe_force_mult_depth;
                    std::cout << "[QueryPlan] MULT_DEPTH OVERRIDE: " << plan.mult_depth << std::endl;
                }
                if (FLAGS_fhe_force_ring_dim > 0 || FLAGS_fhe_force_mult_depth > 0) {
                    plan.ct_size_bytes = vaultdb::ctBytes(plan.ring_dim, plan.mult_depth);
                    plan.working_set_filter_bytes = static_cast<size_t>(
                        vaultdb::workingSetFilter(plan.ring_dim, plan.mult_depth, 3.0));
                    plan.working_set_agg_bytes = static_cast<size_t>(
                        vaultdb::workingSetAgg(plan.ring_dim, plan.mult_depth, 2.0));
                    if (sp.is_loaded && sp.l3_cache_bytes > 0) {
                        double l3 = static_cast<double>(sp.l3_cache_bytes);
                        plan.rho_filter = static_cast<double>(plan.working_set_filter_bytes) / l3;
                        plan.rho_agg = static_cast<double>(plan.working_set_agg_bytes) / l3;
                        plan.fits_l3 = (plan.rho_filter <= 1.05);
                    }
                }

                vaultdb::setCurrentQueryPlan(plan);
                vaultdb::printQueryPlan(plan, sp);
                manager_->initializeForQuery(query_name, plan.ring_dim, plan.mult_depth);
            }
        }
    }

    if (FLAGS_fhe_single_party) {
        // Single-server mode: no B/C, just generate keys locally
        log->write("[FheBaseTest] Single-party mode: local key gen, no network", Level::INFO);
        manager_->generateKeys();
        db_name_ = FLAGS_unioned_db.empty() ? "tpch_unioned_150" : FLAGS_unioned_db;
        get_log()->write("[FheBaseTest] Using database: " + db_name_, Level::INFO);
        return;
    }

    if (party == 1) {
        // ======================================================================
        // Party A (Client): Always connects to B and C for key distribution.
        // Later (runTest): A receives result_mode from B; MPC => uses both B and C,
        // FHE-only => uses B only (C connection established but not used for result).
        // ======================================================================
        log->write("[FheBaseTest] Party A (Client): Starting 3-party setup...", Level::INFO);

        // generateKeys() uses the ring_dim/mult_depth set by initializeForQuery above
        // Generate keys for test independence (each test should have fresh keys)
        manager_->generateKeys();
        std::cout << "[FheBaseTest] Party A: Keys generated for new test" << std::endl;

        try {
            // 1. Connect to Party B (with retry for multi-test: B may still be in TearDown/SetUp)
            const int kConnectMaxRetries = 15;
            const auto kConnectRetryDelay = std::chrono::milliseconds(500);
            std::unique_ptr<FheNetworkIO> network_B;
            for (int attempt = 0; attempt < kConnectMaxRetries; ++attempt) {
                try {
                    network_B = std::make_unique<FheNetworkIO>(bob_host, port_B, false);
                    break;
                } catch (const std::exception& e) {
                    if (attempt == kConnectMaxRetries - 1) throw;
                    std::cout << "[FheBaseTest] Party A: Connect to B failed (attempt " << (attempt + 1)
                              << "/" << kConnectMaxRetries << "), retrying in " << kConnectRetryDelay.count()
                              << "ms: " << e.what() << std::endl;
                    std::this_thread::sleep_for(kConnectRetryDelay);
                }
            }
            std::cout << "[FheBaseTest] Party A: Connected to Party B" << std::endl;

            // 2. Connect to Party C (with retry)
            std::unique_ptr<FheNetworkIO> network_C;
            for (int attempt = 0; attempt < kConnectMaxRetries; ++attempt) {
                try {
                    network_C = std::make_unique<FheNetworkIO>(charlie_host, port_C, false);
                    break;
                } catch (const std::exception& e) {
                    if (attempt == kConnectMaxRetries - 1) throw;
                    std::cout << "[FheBaseTest] Party A: Connect to C failed (attempt " << (attempt + 1)
                              << "/" << kConnectMaxRetries << "), retrying in " << kConnectRetryDelay.count()
                              << "ms: " << e.what() << std::endl;
                    std::this_thread::sleep_for(kConnectRetryDelay);
                }
            }
            std::cout << "[FheBaseTest] Party A: Connected to Party C" << std::endl << std::flush;

            // 3. Serialize Public Data (Context, PK, EvalKeys)
            std::cout << "[FheBaseTest] Party A: Serializing CC/PK (ring_dim=65536 may take 1-2 min)..." << std::endl << std::flush;
            auto cc = manager_->getComparisonCryptoContext();
            auto pk = manager_->getComparisonPublicKey();

            std::ostringstream cc_oss, pk_oss, evalmult_oss, evalrot_oss;
            lbcrypto::Serial::Serialize(cc, cc_oss, lbcrypto::SerType::BINARY);
            std::cout << "[FheBaseTest] Party A: CC serialized (" << cc_oss.str().size() << " bytes)" << std::endl << std::flush;
            lbcrypto::Serial::Serialize(pk, pk_oss, lbcrypto::SerType::BINARY);
            std::cout << "[FheBaseTest] Party A: PK serialized" << std::endl << std::flush;

            std::string evalmult_str = "";
            if (cc->SerializeEvalMultKey(evalmult_oss, lbcrypto::SerType::BINARY)) {
                evalmult_str = evalmult_oss.str();
            }
            std::cout << "[FheBaseTest] Party A: EvalMultKey serialized (" << evalmult_str.size() << " bytes)" << std::endl << std::flush;

            std::string evalrot_str = "";
            if (cc->SerializeEvalAutomorphismKey(evalrot_oss, lbcrypto::SerType::BINARY)) {
                evalrot_str = evalrot_oss.str();
            }
            std::cout << "[FheBaseTest] Party A: EvalRotateKey serialized (" << evalrot_str.size() << " bytes)" << std::endl << std::flush;

            // 4. Send Public Data: B gets full set (cc, pk, evalmult, evalrot); C only cc (decrypt-only, no pk/keys).
            std::cout << "[FheBaseTest] Party A: Sending CC to B..." << std::endl << std::flush;
            network_B->sendString(cc_oss.str());
            network_B->sendString(pk_oss.str());
            network_B->sendString(evalmult_str);
            network_B->sendString(evalrot_str);

            network_C->sendString(cc_oss.str());
            // C: skip pk, evalmult, evalrot (C only needs cc + sk_share for partial decrypt)

            std::cout << "[FheBaseTest] Party A: Public keys sent to B; CC only to C" << std::endl;

            // 5. Secret Key Splitting & Distribution
            std::cout << "[FheBaseTest] Party A: Splitting Secret Key..." << std::endl;
            auto full_sk = manager_->getComparisonSecretKey();
            if (!full_sk) {
                throw std::runtime_error("Party A: Comparison secret key is null");
            }
            auto shares = SplitSecretKey(full_sk, cc);

            // Send Share B to Party B
            std::ostringstream sk_b_oss;
            lbcrypto::Serial::Serialize(shares.first, sk_b_oss, lbcrypto::SerType::BINARY);
            network_B->sendString(sk_b_oss.str());
            std::cout << "[FheBaseTest] Party A: Secret key share sent to Party B" << std::endl;

            // Send Share C to Party C
            std::ostringstream sk_c_oss;
            lbcrypto::Serial::Serialize(shares.second, sk_c_oss, lbcrypto::SerType::BINARY);
            network_C->sendString(sk_c_oss.str());
            std::cout << "[FheBaseTest] Party A: Secret key share sent to Party C" << std::endl;

            // Receive ACK from both parties
            std::cout << "[FheBaseTest] Party A: B ACK: " << network_B->recvString() << std::endl;
            std::cout << "[FheBaseTest] Party A: C ACK: " << network_C->recvString() << std::endl;

            // 6. Send extra RNS contexts (channels 1..N-1) to B and C so they can encrypt large aggregates
            const size_t num_rns = manager_->getRnsCount();
            const size_t num_extra = (num_rns > 1) ? num_rns - 1 : 0;
            const std::string num_extra_str = std::to_string(num_extra);
            network_B->sendString(num_extra_str);
            network_C->sendString(num_extra_str);
            if (num_extra > 0) {
                for (size_t i = 1; i < num_rns; ++i) {
                    auto ctx = manager_->getRnsContext(i);
                    auto kp = manager_->getRnsKeyPair(i);
                    std::ostringstream cc_oss, pk_oss, evalmult_oss, evalrot_oss;
                    lbcrypto::Serial::Serialize(ctx, cc_oss, lbcrypto::SerType::BINARY);
                    lbcrypto::Serial::Serialize(kp.publicKey, pk_oss, lbcrypto::SerType::BINARY);
                    std::string evalmult_str;
                    if (ctx->SerializeEvalMultKey(evalmult_oss, lbcrypto::SerType::BINARY)) {
                        evalmult_str = evalmult_oss.str();
                    }
                    std::string evalrot_str;
                    if (ctx->SerializeEvalAutomorphismKey(evalrot_oss, lbcrypto::SerType::BINARY)) {
                        evalrot_str = evalrot_oss.str();
                    }
                    // B: CC -> PK -> MultKey -> RotKey. C: CC and sk_share only (decrypt-only).
                    network_B->sendString(cc_oss.str());
                    network_B->sendString(pk_oss.str());
                    network_B->sendString(evalmult_str);
                    network_B->sendString(evalrot_str);
                    network_C->sendString(cc_oss.str());
                    // C: skip pk, evalmult, evalrot for this channel
                    auto shares = SplitSecretKey(kp.secretKey, ctx);
                    std::ostringstream sk_b_oss, sk_c_oss;
                    lbcrypto::Serial::Serialize(shares.first, sk_b_oss, lbcrypto::SerType::BINARY);
                    lbcrypto::Serial::Serialize(shares.second, sk_c_oss, lbcrypto::SerType::BINARY);
                    network_B->sendString(sk_b_oss.str());
                    network_C->sendString(sk_c_oss.str());
                }
                std::cout << "[FheBaseTest] Party A: RNS channels 1.." << num_extra << " sent to B (full keys), C (cc+sk only)" << std::endl;
            }

            // Phase 3.1–3.2: Receive dict version from Party B, sync if needed
            std::string server_dict_version = network_B->recvString();
            std::cout << "[FheBaseTest] Party A: Server dict version " << server_dict_version << std::endl;
            {
                std::string dict_path = Utilities::getCurrentWorkingDirectory() +
                    "/conf/plans/fhe/tpch_metadata_dictionary.json";
                auto& dm = DictionaryManager::getInstance();
                if (!dm.isLoaded() || dm.getVersion() != server_dict_version) {
                    dm.load(dict_path);
                    std::cout << "[FheBaseTest] Party A: Dict (re)loaded, version=" << dm.getVersion() << std::endl;
                }
            }

            // Set network_io_ to Party B connection for query execution
            network_io_ = std::move(network_B);
            // Keep Party C connection for direct share transfer
            network_io_charlie_ = std::move(network_C);
            SystemConfiguration::getInstance().setFheNetworkIO(network_io_.get());

        } catch (const std::exception& e) {
            log->write("[FheBaseTest] Party A: Setup failed: " + std::string(e.what()), Level::ERROR);
            throw;
        }

        db_name_ = empty_db_;

    } else if (party == 2 || party == 3) {
        // ======================================================================
        // Party B (Server B) and Party C (Server C): Receive keys from Party A
        // ======================================================================
        int my_port = (party == 2) ? port_B : port_C;
        std::string role = (party == 2) ? "Party B" : "Party C";

        log->write("[FheBaseTest] " + role + ": Starting 3-party setup...", Level::INFO);
        log->write("[FheBaseTest] " + role + ": Waiting on port " + std::to_string(my_port), Level::INFO);

        // Clear any previous context before receiving new one (ensures clean state)
        cc_from_party_A_ = CryptoContext<DCRTPoly>();
        pk_from_party_A_ = PublicKey<DCRTPoly>();
        
        // Also reset FheManager's context if it exists (should already be reset in TearDown, but defensive)
        if (manager_) {
            manager_->resetBFVContext();
        }

        try {
            network_io_ = std::make_unique<FheNetworkIO>("0.0.0.0", my_port, true);
            SystemConfiguration::getInstance().setFheNetworkIO(network_io_.get());
            std::cout << "[FheBaseTest] " << role << ": Accepted connection from Party A" << std::endl << std::flush;

            // 1. Receive and deserialize Public Data (CC, PK, EvalKeys)
            std::cout << "[FheBaseTest] " << role << ": Waiting for CC from Party A..." << std::endl << std::flush;
            std::string cc_serialized = network_io_->recvString();
            std::istringstream cc_iss(cc_serialized);
            lbcrypto::Serial::Deserialize(cc_from_party_A_, cc_iss, lbcrypto::SerType::BINARY);
            std::cout << "[FheBaseTest] " << role << ": CryptoContext deserialized and stored" << std::endl;
            cc_from_party_A_->Enable(PKESchemeFeature::MULTIPARTY);
            cc_from_party_A_->Enable(PKE);
            cc_from_party_A_->Enable(KEYSWITCH);
            cc_from_party_A_->Enable(LEVELEDSHE);
            cc_from_party_A_->Enable(ADVANCEDSHE);
            std::cout << "[FheBaseTest] " << role << ": MULTIPARTY and PKE/KEYSWITCH/LEVELEDSHE/ADVANCEDSHE enabled" << std::endl;

            if (party == 2) {
                std::string pk_serialized = network_io_->recvString();
                std::istringstream pk_iss(pk_serialized);
                lbcrypto::Serial::Deserialize(pk_from_party_A_, pk_iss, lbcrypto::SerType::BINARY);
                std::cout << "[FheBaseTest] " << role << ": Public key deserialized and stored" << std::endl;

                std::string evalmult_serialized = network_io_->recvString();
                if (!evalmult_serialized.empty()) {
                    std::istringstream evalmult_iss(evalmult_serialized);
                    if (!cc_from_party_A_->DeserializeEvalMultKey(evalmult_iss, lbcrypto::SerType::BINARY)) {
                        throw std::runtime_error(role + ": Failed to load EvalMultKeys - keys may already be registered (TearDown cleanup issue)");
                    }
                    std::cout << "[FheBaseTest] " << role << ": EvalMultKeys loaded into Party A's context" << std::endl;
                }

                std::string evalrot_serialized = network_io_->recvString();
                if (!evalrot_serialized.empty()) {
                    std::istringstream evalrot_iss(evalrot_serialized);
                    if (!cc_from_party_A_->DeserializeEvalAutomorphismKey(evalrot_iss, lbcrypto::SerType::BINARY)) {
                        throw std::runtime_error(role + ": Failed to load EvalAutomorphismKeys - keys may already be registered (TearDown cleanup issue)");
                    }
                    std::cout << "[FheBaseTest] " << role << ": EvalAutomorphismKeys loaded into Party A's context" << std::endl;
                }
            }
            // Party C: A does not send pk/evalmult/evalrot; C only needs cc + sk_share for partial decrypt

            // 2. Receive Secret Key Share
            std::string sk_share_serialized = network_io_->recvString();
            std::istringstream sk_share_iss(sk_share_serialized);
            lbcrypto::PrivateKey<lbcrypto::DCRTPoly> my_sk_share;
            lbcrypto::Serial::Deserialize(my_sk_share, sk_share_iss, lbcrypto::SerType::BINARY);
            std::cout << "[FheBaseTest] " << role << ": Received Secret Key Share" << std::endl;

            // Store the secret key share in member variable for later use in distributed decryption
            my_secret_key_share_ = my_sk_share;

            // Set up FheManager with Party A's context
            manager_->resetBFVContext();
            manager_->setBFVCryptoContext(cc_from_party_A_);
            if (party == 2) {
                manager_->setBFVPublicKey(pk_from_party_A_);
            } else {
                manager_->setDecryptOnlyMode(true);  // Party C: blank public key (decrypt-only; getBFVPublicKey returns default)
            }

            network_io_->sendString("Setup OK");
            std::cout << "[FheBaseTest] " << role << ": Setup complete" << std::endl;

            // 3. Receive extra RNS contexts from Party A (for 64-bit aggregation on B/C)
            std::string num_extra_str = network_io_->recvString();
            if (!num_extra_str.empty() && num_extra_str != "0") {
                size_t num_extra = 0;
                try { num_extra = static_cast<size_t>(std::stoul(num_extra_str)); } catch (...) {}
                if (num_extra > 0) {
                    std::vector<CryptoContext<DCRTPoly>> extra_contexts;
                    std::vector<PublicKey<DCRTPoly>> extra_pks;
                    std::vector<PrivateKey<DCRTPoly>> extra_sk_shares;
                    extra_contexts.reserve(num_extra);
                    extra_pks.reserve(num_extra);
                    extra_sk_shares.reserve(num_extra);
                    for (size_t i = 0; i < num_extra; ++i) {
                        std::string cc_ser = network_io_->recvString();
                        std::istringstream cc_iss(cc_ser);
                        CryptoContext<DCRTPoly> ecc;
                        lbcrypto::Serial::Deserialize(ecc, cc_iss, lbcrypto::SerType::BINARY);
                        ecc->Enable(PKESchemeFeature::MULTIPARTY);
                        ecc->Enable(PKE);
                        ecc->Enable(KEYSWITCH);
                        ecc->Enable(LEVELEDSHE);
                        ecc->Enable(ADVANCEDSHE);
                        extra_contexts.push_back(ecc);
                        if (party == 2) {
                            std::string pk_ser = network_io_->recvString();
                            std::istringstream pk_iss(pk_ser);
                            PublicKey<DCRTPoly> epk;
                            lbcrypto::Serial::Deserialize(epk, pk_iss, lbcrypto::SerType::BINARY);
                            extra_pks.push_back(epk);
                            std::string evalmult_ser = network_io_->recvString();
                            if (!evalmult_ser.empty()) {
                                // Global clear required: InsertEvalMultKey throws on duplicate keyTag
                                try { extra_contexts.back()->ClearEvalMultKeys(); } catch (...) {}
                                std::istringstream evalmult_iss(evalmult_ser);
                                extra_contexts.back()->DeserializeEvalMultKey(evalmult_iss, lbcrypto::SerType::BINARY);
                            }
                            std::string evalrot_ser = network_io_->recvString();
                            if (!evalrot_ser.empty()) {
                                // NO clear: InsertEvalAutomorphismKey merges safely.
                                // The old no-arg ClearEvalAutomorphismKeys() wiped ALL channels'
                                // rotation keys, leaving only the last channel functional.
                                std::istringstream evalrot_iss(evalrot_ser);
                                extra_contexts.back()->DeserializeEvalAutomorphismKey(evalrot_iss, lbcrypto::SerType::BINARY);
                            }
                        }
                        std::string sk_ser = network_io_->recvString();
                        std::istringstream sk_iss(sk_ser);
                        PrivateKey<DCRTPoly> esk;
                        lbcrypto::Serial::Deserialize(esk, sk_iss, lbcrypto::SerType::BINARY);
                        extra_sk_shares.push_back(esk);
                    }
                    if (party == 2) {
                        manager_->setRnsFromPartyA(cc_from_party_A_, pk_from_party_A_, my_secret_key_share_,
                            extra_contexts, extra_pks, extra_sk_shares);
                    } else {
                        manager_->setRnsFromPartyADecryptOnly(cc_from_party_A_, my_secret_key_share_,
                            extra_contexts, extra_sk_shares);
                    }
                }
            }

            if (party == 2) {
                // Send dictionary version for client sync (Phase 3.1)
                std::string dict_path = Utilities::getCurrentWorkingDirectory() +
                    "/conf/plans/fhe/tpch_metadata_dictionary.json";
                std::string dict_version = "0";
                if (std::ifstream f(dict_path); f.good()) {
                    DictionaryManager::getInstance().load(dict_path);
                    dict_version = DictionaryManager::getInstance().getVersion();
                    if (dict_version.empty()) dict_version = "0";
                }
                network_io_->sendString(dict_version);
                std::cout << "[FheBaseTest] Party B: Sent dict version " << dict_version << std::endl;
                receivePredicates();
            }

        } catch (const std::exception& e) {
            log->write("[FheBaseTest] " + role + ": Setup failed: " + std::string(e.what()), Level::ERROR);
            throw;
        }

        if (FLAGS_unioned_db.empty()) {
            db_name_ = "tpch_unioned_150";
        } else {
            db_name_ = FLAGS_unioned_db;
        }

    } else {
        throw std::runtime_error("Invalid party: must be 1, 2, or 3");
    }
}

void FheBaseTest::TearDown() {
    SystemConfiguration& s = SystemConfiguration::getInstance();
    
    // Release FheManager's reference first to reduce reference count
    if (manager_) {
        manager_->resetBFVContext();
    }

    // Party B and Party C (Servers): Explicitly clear keys from Party A's context
    // OpenFHE uses KeyTag(ID) internally to manage keys in a static map/cache.
    // Simply resetting CryptoContext to nullptr doesn't remove the KeyTag.
    // We must explicitly clear keys to prevent key collision in the next test.
    if ((s.party_ == 2 || s.party_ == 3) && cc_from_party_A_) {
        std::cout << "[FheBaseTest] TearDown: Clearing keys from Party A's context..." << std::endl;
        
        try {
            cc_from_party_A_->ClearEvalMultKeys();
            std::cout << "[FheBaseTest] TearDown: EvalMultKeys cleared" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "[FheBaseTest] TearDown: ClearEvalMultKeys failed or not available: " << e.what() << std::endl;
        }
        
        try {
            cc_from_party_A_->ClearEvalAutomorphismKeys();
            std::cout << "[FheBaseTest] TearDown: EvalAutomorphismKeys cleared" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "[FheBaseTest] TearDown: ClearEvalAutomorphismKeys failed or not available: " << e.what() << std::endl;
        }
        
        std::cout << "[FheBaseTest] TearDown: Keys cleared." << std::endl;
    }

    // Reset all state for test independence
    if (network_io_) {
        network_io_.reset();
    }
    
    if (mpc_network_io_) {
        mpc_network_io_.reset();
    }
    
    encrypted_predicates_map_.clear();
    cc_from_party_A_ = CryptoContext<DCRTPoly>();
    pk_from_party_A_ = PublicKey<DCRTPoly>();
    my_secret_key_share_ = PrivateKey<DCRTPoly>();
    s.setFheNetworkIO(nullptr);
    
    std::cout << "[FheBaseTest] TearDown: All state reset for next test" << std::endl;
}

// Default implementation: do nothing (derived classes override to send predicates)
void FheBaseTest::sendPredicates() {
    // Default: send count 0 (no predicates)
    int count = 0;
    if (network_io_) {
        network_io_->sendData(&count, sizeof(int));
        std::cout << "[FheBaseTest] Party A: No predicates to send (override sendPredicates() to send predicates)" << std::endl;
    }
}

namespace {
// Strip predicate suffix from wire key to get Dict column (e.g. "o_orderdate_less_than" -> "o_orderdate")
// Loops until stable so multi-level wire keys like "p_container_0_in_0" strip correctly:
//   p_container_0_in_0 -> p_container_0_in -> p_container_0 -> p_container
std::string getDictColumnFromWireKey(const std::string& column_name) {
    std::string key = column_name;
    const char* suffixes[] = {"_less_than", "_greater_than", "_less_equal", "_greater_equal", "_equal", "_in"};
    for (;;) {
        std::string prev = key;
        // Strip trailing _N index suffix (e.g. "_0", "_1")
        auto last_us = key.rfind('_');
        if (last_us != std::string::npos && last_us + 1 < key.size()) {
            bool all_digits = true;
            for (size_t i = last_us + 1; i < key.size(); ++i) {
                if (!std::isdigit(static_cast<unsigned char>(key[i]))) { all_digits = false; break; }
            }
            if (all_digits) {
                key = key.substr(0, last_us);
            }
        }
        // Strip known predicate suffixes
        for (const char* suf : suffixes) {
            size_t len = std::strlen(suf);
            if (key.size() > len &&
                key.compare(key.size() - len, len, suf) == 0) {
                key = key.substr(0, key.size() - len);
                break;
            }
        }
        if (key == prev) break;  // stable
    }
    return key;
}
}  // namespace

void FheBaseTest::sendPredicatesFromVector(const std::vector<PredicateDef>& predicates) {
    SystemConfiguration &s = SystemConfiguration::getInstance();
    if (s.party_ != 1) {
        return;  // Only Party A sends predicates
    }

    auto* net = getNetworkIO();
    if (!net) {
        throw std::runtime_error("Party A: Network IO not available for sending predicates");
    }

    FheManager& manager = FheManager::getInstance();
    size_t rns_count = manager.getRnsCount();
    size_t pack_slots = manager.getBFVComparisonBatchSize();

    int count = predicates.size();
    net->sendData(&count, sizeof(int));
    std::cout << "[FheBaseTest] Party A: Sending " << count << " predicate(s)" << std::endl;

    if (count == 0) {
        return;
    }

    for (const auto& pred_def : predicates) {
        std::string column_name = pred_def.column_name;
        std::string predicate_type = pred_def.predicate_type;
        std::string threshold_str = pred_def.threshold_value;
        size_t radix_base;
        size_t num_digits;

        auto& dm = DictionaryManager::getInstance();
        if (!dm.isLoaded()) {
            std::string dict_path = Utilities::getCurrentWorkingDirectory() +
                "/conf/plans/fhe/tpch_metadata_dictionary.json";
            dm.load(dict_path);
        }
        if (!dm.isLoaded()) {
            throw std::runtime_error("[FheBaseTest] Party A: Dictionary not loaded, cannot resolve " +
                pred_def.table_name + "." + column_name);
        }
        std::string dict_col = getDictColumnFromWireKey(column_name);
        int64_t threshold_relative = dm.valueToInt64(pred_def.table_name, dict_col, threshold_str);
        auto strat = dm.getStrategy(pred_def.table_name, dict_col);
        radix_base = static_cast<size_t>(strat.first);
        num_digits = static_cast<size_t>(strat.second);

        auto digits = encodeRadixDigits(threshold_relative, radix_base, num_digits);

        std::cout << "[FheBaseTest] Party A: Encrypting predicate: column=" << column_name
                  << ", type=" << predicate_type
                  << ", threshold=" << threshold_str
                  << ", radix_base=" << radix_base
                  << ", num_digits=" << num_digits
                  << ", channels=" << rns_count << std::endl;

        net->sendString(column_name);
        size_t radix_info[2] = {radix_base, num_digits};
        net->sendData(radix_info, sizeof(radix_info));
        net->sendData(&rns_count, sizeof(rns_count));

        for (size_t ch = 0; ch < rns_count; ++ch) {
            auto cc_ch = manager.getRnsContext(ch);
            auto pk_ch = manager.getRnsKeyPair(ch).publicKey;
            for (size_t d = 0; d < num_digits; ++d) {
                std::vector<int64_t> digit_vec(pack_slots, digits[d]);
                lbcrypto::Plaintext pt_plain = cc_ch->MakePackedPlaintext(digit_vec);
                auto encrypted_digit = cc_ch->Encrypt(pk_ch, pt_plain);
                std::ostringstream oss;
                lbcrypto::Serial::Serialize(encrypted_digit, oss, lbcrypto::SerType::BINARY);
                net->sendString(oss.str());
            }
        }
    }

    std::string ack = net->recvString();
    std::cout << "[FheBaseTest] Party A: Received acknowledgment: " << ack << std::endl;
}

PredicateDef FheBaseTest::buildPredicateDefFromSQL(const std::string& table,
    const std::string& column, const std::string& op, const std::string& value,
    const std::string& wire_key) {
    PredicateDef def;
    def.table_name = table;
    def.column_name = wire_key.empty() ? column : wire_key;
    def.predicate_type = op;
    def.threshold_value = value;
    return def;
}

std::string FheBaseTest::generateExpectedOutputQuery(const int& test_id, const std::string& db_name) {
    std::ostringstream test_id_stream;
    test_id_stream << std::setw(2) << std::setfill('0') << test_id;
    std::string test_id_str = test_id_stream.str();

    // Prefer FHE-specific expected query (matches plan output schema)
    std::string base_path = Utilities::getCurrentWorkingDirectory() + "/conf/sql/tpch/q" + test_id_str;
    std::string query_file_path = base_path + ".sql";
    std::ifstream query_file(query_file_path);
    if (!query_file.is_open()) {
        query_file_path = base_path + ".sql";
        query_file.open(query_file_path);
    }
    if (!query_file.is_open()) {
        throw std::runtime_error("Could not open query file: " + query_file_path);
    }

    std::stringstream query_buffer;
    query_buffer << query_file.rdbuf();
    std::string query = query_buffer.str();
    query_file.close();

    boost::replace_all(query, "$UNIONED_DB", db_name);
    return query;
}

void FheBaseTest::receivePredicates() {
    if (!network_io_) {
        return;
    }
    
    Logger* log = get_log();
    
    // 1. Receive predicate count
    int count = 0;
    network_io_->recvData(&count, sizeof(int));
    std::cout << "[FheBaseTest] Party B: Receiving " << count << " predicate(s)" << std::endl;
    log->write("[FheBaseTest] Party B: Receiving " + std::to_string(count) + " predicate(s)", Level::INFO);
    
    // Use Party A's context to deserialize ciphertexts (they were encrypted with Party A's public key)
    // Important: ciphertexts must be deserialized with the same context that was used to encrypt them
    if (!cc_from_party_A_) {
        throw std::runtime_error("[FheBaseTest] Party B: Party A's CryptoContext not available for predicate deserialization");
    }
    
    // 2. Receive each predicate
    FheManager& manager = FheManager::getInstance();
    for (int i = 0; i < count; ++i) {
        // 2-1. Receive column name (key)
        std::string column_name = network_io_->recvString();
        std::cout << "[FheBaseTest] Party B: Receiving predicate for column: " << column_name << std::endl;
        log->write("[FheBaseTest] Party B: Receiving predicate for column: " + column_name, Level::INFO);
        
        // 2-2. Receive metadata (radix_base, num_digits, num_channels)
        size_t meta[2];
        network_io_->recvData(meta, sizeof(meta));
        size_t radix_base = meta[0];
        size_t num_digits = meta[1];
        size_t num_channels = 1;
        network_io_->recvData(&num_channels, sizeof(num_channels));
        std::cout << "[FheBaseTest] Party B: Metadata - radix_base=" << radix_base
                  << ", num_digits=" << num_digits << ", channels=" << num_channels << std::endl;
        
        EncryptedPredicate ep;
        ep.radix_base = radix_base;
        ep.num_digits = num_digits;
        ep.digits_per_channel.resize(num_channels);
        for (size_t ch = 0; ch < num_channels; ++ch) {
            ep.digits_per_channel[ch].reserve(num_digits);
            for (size_t d = 0; d < num_digits; ++d) {
                std::string ct_str = network_io_->recvString();
                std::istringstream ct_iss(ct_str);
                lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ct;
                lbcrypto::Serial::Deserialize(ct, ct_iss, lbcrypto::SerType::BINARY);
                ep.digits_per_channel[ch].push_back(ct);
            }
        }
        ep.digits = ep.digits_per_channel[0];
        encrypted_predicates_map_[column_name] = std::move(ep);
        std::cout << "[FheBaseTest] Party B: Predicate stored for column: " << column_name
                  << " (" << num_digits << " digits, " << num_channels << " channel(s))" << std::endl;
        log->write("[FheBaseTest] Party B: Predicate stored for column: " + column_name, Level::INFO);
    }
    
    // Send acknowledgment
    if (count > 0) {
        network_io_->sendString("Predicates received successfully");
        std::cout << "[FheBaseTest] Party B: All predicates received and stored" << std::endl;
        log->write("[FheBaseTest] Party B: All predicates received and stored", Level::INFO);
    }
}

void FheBaseTest::TearDownTestSuite() {
    // No need to delete singleton
    SystemConfiguration::getInstance().crypto_manager_ = nullptr;
    manager_ = nullptr;
}

void FheBaseTest::disableBitPacking() {
    SystemConfiguration &s = SystemConfiguration::getInstance();
    s.clearBitPacking();
}

std::vector<LWECiphertext> FheBaseTest::EncryptBits(const std::vector<bool>& bits, const BinFHEContext& cc, const LWEPrivateKey& boolKey) {
    std::vector<LWECiphertext> ciphertexts;
    for (bool bit : bits) {
        ciphertexts.push_back(cc.Encrypt(boolKey, bit));
    }
    return ciphertexts;
}

int64_t FheBaseTest::baseRelativeEpochDays() {
    static const int64_t base_days = []() {
        std::tm timeinfo{};
        timeinfo.tm_year = 1992 - 1900;
        timeinfo.tm_mon = 1 - 1;
        timeinfo.tm_mday = 1;
        timeinfo.tm_hour = 0;
        timeinfo.tm_min = 0;
        timeinfo.tm_sec = 0;
        timeinfo.tm_isdst = -1;
        time_t epoch_seconds = mktime(&timeinfo);
        return static_cast<int64_t>(epoch_seconds / (24 * 3600));
    }();
    return base_days;
}

int64_t FheBaseTest::relativeDaysFromField(const PlainField& field) {
    static const int64_t SECONDS_PER_DAY = 24 * 3600;
    const int64_t base_days = baseRelativeEpochDays();

    switch (field.getType()) {
        case FieldType::DATE:
        case FieldType::LONG: {
            const int64_t raw = field.getValue<int64_t>();
            if (std::llabs(raw) < 10000) {
                return raw;
            }
            const int64_t epoch_days = raw / SECONDS_PER_DAY;
            return epoch_days - base_days;
        }
        case FieldType::INT: {
            const int32_t raw = field.getValue<int32_t>();
            if (raw > 10000) {
                const int year = raw / 10000;
                const int month = (raw / 100) % 100;
                const int day = raw % 100;
                std::tm timeinfo{};
                timeinfo.tm_year = year - 1900;
                timeinfo.tm_mon = month - 1;
                timeinfo.tm_mday = day;
                timeinfo.tm_hour = 0;
                timeinfo.tm_min = 0;
                timeinfo.tm_sec = 0;
                timeinfo.tm_isdst = -1;
                time_t epoch_seconds = mktime(&timeinfo);
                const int64_t epoch_days = epoch_seconds / SECONDS_PER_DAY;
                return epoch_days - base_days;
            }
            return static_cast<int64_t>(raw);
        }
        default:
            return static_cast<int64_t>(field.getValue<int64_t>());
    }
}

void FheBaseTest::normalizeDateColumn(PlainColumnTable& table, const std::string& column_name) {
    auto column = table.getPlainColumn(column_name);
    if (!column) {
        return;
    }

    for (const auto& chunk : column->getPlainChunks()) {
        if (!chunk) continue;
        auto& values = const_cast<std::vector<PlainField>&>(chunk->getValues());
        for (auto& field : values) {
            const int64_t relative = relativeDaysFromField(field);
            field = PlainField(FieldType::LONG, relative);
        }
    }
}

void FheBaseTest::normalizeDateColumns(PlainColumnTable& table, const std::vector<std::string>& column_names) {
    for (const auto& name : column_names) {
        normalizeDateColumn(table, name);
    }
}

void FheBaseTest::normalizeDateColumnsAuto(PlainColumnTable& table) {
    const QuerySchema& schema = table.getSchema();
    for (int idx = 0; idx < schema.getFieldCount(); ++idx) {
        const auto& desc = schema.getField(idx);
        const std::string lowered = boost::algorithm::to_lower_copy(desc.getName());
        if (desc.getType() == FieldType::DATE || lowered.find("date") != std::string::npos) {
            normalizeDateColumn(table, desc.getName());
        }
    }
}

void FheBaseTest::sendResultTable(std::shared_ptr<FheColumnTable> result_table) {
    if (!network_io_ || !result_table) {
        return;
    }
    
    std::cout << "[FheBaseTest] Party B: Sending result table to Party A" << std::endl;
    
    // Use Party A's context for serialization (ciphertexts are encrypted with Party A's public key)
    if (!cc_from_party_A_) {
        throw std::runtime_error("[FheBaseTest] Party B: Party A's CryptoContext not available");
    }
    
    const auto& schema = result_table->getSchema();
    // QuerySchema::getFieldCount() excludes dummy_tag. FHE result tables always have dummy_tag; send it so Party A can filter valid rows.
    const int field_count = schema.getFieldCount() + 1;
    size_t row_count = result_table->getRowCount();
    
    // 1. Send schema metadata
    network_io_->sendData(&field_count, sizeof(int));
    network_io_->sendData(&row_count, sizeof(size_t));
    
    // Send field information (ordinals 0..N-1, then dummy_tag)
    for (int i = 0; i < schema.getFieldCount(); ++i) {
        const auto& field = schema.getField(i);
        network_io_->sendString(field.getName());
        int field_type = static_cast<int>(field.getType());
        network_io_->sendData(&field_type, sizeof(int));
        network_io_->sendString(field.getTableName());
        int string_len = static_cast<int>(field.getStringLength());
        network_io_->sendData(&string_len, sizeof(int));
    }
    {
        const auto& field = schema.getField("dummy_tag");
        network_io_->sendString(field.getName());
        int field_type = static_cast<int>(field.getType());
        network_io_->sendData(&field_type, sizeof(int));
        network_io_->sendString(field.getTableName());
        int string_len = static_cast<int>(field.getStringLength());
        network_io_->sendData(&string_len, sizeof(int));
    }
    
    // 2. Send all columns in same order (plain + encrypted) so Party A can reconstruct the full table
    int num_columns = field_count;
    network_io_->sendData(&num_columns, sizeof(int));

    auto plain_snapshot = result_table->getPlainSnapshot();
    auto sendOneColumn = [&](const QueryFieldDesc& fd, const std::string& col_name) {
        network_io_->sendString(col_name);

        bool has_enc = result_table->hasEncryptedColumn(col_name);
        std::shared_ptr<PlainColumn> plain_col;
        if (plain_snapshot) {
            plain_col = plain_snapshot->getPlainColumn(col_name);
        }
        bool is_plain = (!has_enc && plain_col);
        int is_plain_int = is_plain ? 1 : 0;
        network_io_->sendData(&is_plain_int, sizeof(int));

        if (is_plain) {
            // Send plain column: row_count, field_type, then int64 values (one per row)
            size_t rc = result_table->getRowCount();
            network_io_->sendData(&rc, sizeof(size_t));
            int ft = static_cast<int>(fd.getType());
            network_io_->sendData(&ft, sizeof(int));
            for (const auto& chunk : plain_col->getPlainChunks()) {
                if (!chunk) continue;
                for (const auto& f : chunk->getValues()) {
                    int64_t v = 0;
                    switch (fd.getType()) {
                        case FieldType::INT:   v = static_cast<int64_t>(f.getValue<int32_t>()); break;
                        case FieldType::LONG:
                        case FieldType::DATE: v = f.getValue<int64_t>(); break;
                        case FieldType::BOOL:  v = f.getValue<bool>() ? 1 : 0; break;
                        case FieldType::FLOAT: v = static_cast<int64_t>(std::round(f.getValue<float_t>() * 100.0)); break;
                        default: v = f.getValue<int64_t>(); break;
                    }
                    network_io_->sendData(&v, sizeof(int64_t));
                }
            }
        } else {
            // Send encrypted column: num_chunks, then per-chunk rns_level + that many ciphertexts
            auto fhe_col = result_table->getFheColumn(col_name);
            if (!fhe_col) {
                throw std::runtime_error("[FheBaseTest] Party B: column " + col_name + " is neither plain nor encrypted");
            }
            const auto& chunks = fhe_col->getFheChunks();
            int num_chunks = static_cast<int>(chunks.size());
            network_io_->sendData(&num_chunks, sizeof(int));
            for (const auto& chunk : chunks) {
                if (!chunk || !chunk->getFheValue()) {
                    throw std::runtime_error("[FheBaseTest] Party B: Invalid chunk in column " + col_name);
                }
                size_t rns_level = chunk->getRnsLevel();
                network_io_->sendData(&rns_level, sizeof(size_t));
                for (size_t ch = 0; ch < rns_level; ++ch) {
                    auto ct = chunk->getCiphertext(ch);
                    std::ostringstream ct_oss;
                    lbcrypto::Serial::Serialize(ct, ct_oss, lbcrypto::SerType::BINARY);
                    network_io_->sendString(ct_oss.str());
                }
                QuantizationParams qp = chunk->q_params();
                FheTypeDescriptor td = chunk->type_desc;
                size_t packed_count = chunk->packed_count;
                network_io_->sendData(&qp, sizeof(QuantizationParams));
                network_io_->sendData(&td, sizeof(FheTypeDescriptor));
                network_io_->sendData(&packed_count, sizeof(size_t));
            }
        }
    };
    for (int i = 0; i < schema.getFieldCount(); ++i) {
        const auto& fd = schema.getField(i);
        sendOneColumn(fd, fd.getName());
    }
    sendOneColumn(schema.getField("dummy_tag"), "dummy_tag");
    
    std::cout << "[FheBaseTest] Party B: Result table sent successfully" << std::endl;
}

std::shared_ptr<FheColumnTable> FheBaseTest::receiveResultTable() {
    if (!network_io_) {
        return nullptr;
    }
    
    std::cout << "[FheBaseTest] Party A: Receiving result table from Party B" << std::endl;
    
    auto cc_comp = manager_->getComparisonCryptoContext();
    if (!cc_comp) {
        throw std::runtime_error("[FheBaseTest] Party A: CryptoContext not available");
    }
    
    // 1. Receive schema metadata
    int field_count = 0;
    size_t row_count = 0;
    network_io_->recvData(&field_count, sizeof(int));
    network_io_->recvData(&row_count, sizeof(size_t));
    
    // Build schema
    QuerySchema schema;
    for (int i = 0; i < field_count; ++i) {
        std::string field_name = network_io_->recvString();
        int field_type_int = 0;
        network_io_->recvData(&field_type_int, sizeof(int));
        FieldType field_type = static_cast<FieldType>(field_type_int);
        // Receive table name and string length
        std::string table_name = network_io_->recvString();
        int string_len = 0;
        network_io_->recvData(&string_len, sizeof(int));
        // Construct field with complete metadata
        QueryFieldDesc field_desc(i, field_name, table_name, field_type, string_len);
        schema.putField(field_desc);
    }
    schema.initializeFieldOffsets();
    
    // 2. Create empty FheColumnTable
    auto result_table = std::make_shared<FheColumnTable>(schema, row_count);
    
    // 3. Receive column count (same as field_count; columns sent in schema order)
    int num_columns = 0;
    network_io_->recvData(&num_columns, sizeof(int));

    std::vector<std::pair<std::string, std::shared_ptr<PlainColumn>>> plain_columns;

    // 4. Receive each column (plain or encrypted)
    for (int col_idx = 0; col_idx < num_columns; ++col_idx) {
        std::string col_name = network_io_->recvString();
        int is_plain_int = 0;
        network_io_->recvData(&is_plain_int, sizeof(int));

        if (is_plain_int != 0) {
            // Plain column: row_count, field_type, then int64 values
            size_t rc = 0;
            network_io_->recvData(&rc, sizeof(size_t));
            int ft = 0;
            network_io_->recvData(&ft, sizeof(int));
            FieldType field_type = static_cast<FieldType>(ft);
            std::vector<PlainField> values;
            values.reserve(rc);
            for (size_t r = 0; r < rc; ++r) {
                int64_t v = 0;
                network_io_->recvData(&v, sizeof(int64_t));
                PlainField f;
                switch (field_type) {
                    case FieldType::INT:   f = PlainField(FieldType::INT, static_cast<int32_t>(v)); break;
                    case FieldType::LONG:
                    case FieldType::DATE: f = PlainField(FieldType::LONG, v); break;
                    case FieldType::BOOL:  f = PlainField(FieldType::BOOL, v != 0); break;
                    case FieldType::FLOAT: f = PlainField(FieldType::FLOAT, static_cast<float_t>(v) / 100.0f); break;
                    default: f = PlainField(FieldType::LONG, v); break;
                }
                values.push_back(std::move(f));
            }
            auto plain_chunk = std::make_shared<PlainColumnChunk>(values);
            auto plain_col = std::make_shared<PlainColumn>(col_name);
            plain_col->addChunk(plain_chunk);
            plain_columns.emplace_back(col_name, std::move(plain_col));
        } else {
            // Encrypted column: num_chunks, then per-chunk rns_level + that many ciphertexts
            int num_chunks = 0;
            network_io_->recvData(&num_chunks, sizeof(int));
            auto fhe_col = std::make_shared<FheColumn>(col_name);
            for (int chunk_idx = 0; chunk_idx < num_chunks; ++chunk_idx) {
                size_t rns_level = 0;
                network_io_->recvData(&rns_level, sizeof(size_t));
                std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ciphers;
                ciphers.reserve(rns_level);
                for (size_t ch = 0; ch < rns_level; ++ch) {
                    std::string ct_str = network_io_->recvString();
                    std::istringstream ct_iss(ct_str);
                    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ct;
                    lbcrypto::Serial::Deserialize(ct, ct_iss, lbcrypto::SerType::BINARY);
                    ciphers.push_back(std::move(ct));
                }
                QuantizationParams qp;
                FheTypeDescriptor td;
                size_t packed_count = 0;
                network_io_->recvData(&qp, sizeof(QuantizationParams));
                network_io_->recvData(&td, sizeof(FheTypeDescriptor));
                network_io_->recvData(&packed_count, sizeof(size_t));
                std::shared_ptr<FheColumnChunk> chunk;
                if (ciphers.size() == 1) {
                    chunk = std::make_shared<FheColumnChunk>(std::move(ciphers[0]), qp, td, packed_count);
                } else {
                    chunk = std::make_shared<FheColumnChunk>(ciphers, qp, td, packed_count);
                }
                fhe_col->addFheChunk(chunk);
            }
            result_table->addColumn(fhe_col);
        }
    }

    if (!plain_columns.empty()) {
        auto plain_table = std::make_shared<PlainColumnTable>(schema, row_count);
        for (auto& p : plain_columns) {
            plain_table->addColumn(p.first, std::move(p.second));
        }
        result_table->setPlainTable(std::move(plain_table));
    }
    
    std::cout << "[FheBaseTest] Party A: Result table received successfully" << std::endl;
    return result_table;
}

// Distributed Decryption Protocol: Convert FHE ciphertext to MPC shares
// Uses Masked Exchange technique to ensure neither Party B nor C learns the plaintext
std::pair<lbcrypto::DCRTPoly, lbcrypto::DCRTPoly> FheBaseTest::RunDistributedDecryptionProtocol(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c_agg) {
    
    Logger* log = get_log();
    int party = SystemConfiguration::getInstance().party_;
    
    if (party != 2 && party != 3) {
        throw std::runtime_error("RunDistributedDecryptionProtocol: Must be called by Party B (2) or Party C (3)");
    }
    
    if (!mpc_network_io_) {
        throw std::runtime_error("RunDistributedDecryptionProtocol: MPC network connection not established");
    }
    
    if (!cc_from_party_A_) {
        throw std::runtime_error("RunDistributedDecryptionProtocol: Party A's CryptoContext not available");
    }
    
    // -----------------------------------------------------------------
    // Role: Party B (Leader)
    // -----------------------------------------------------------------
    if (party == 2) {
        std::cout << "[DistributedDecryption] Party B: Starting distributed decryption protocol..." << std::endl;
        
        // [B-1] Extract c0 and c1 from ciphertext
        if (!c_agg) {
            throw std::runtime_error("RunDistributedDecryptionProtocol: Party B must provide a valid ciphertext");
        }
        auto elements = c_agg->GetElements();
        if (elements.size() < 2) {
            throw std::runtime_error("RunDistributedDecryptionProtocol: Ciphertext must have at least 2 elements (c0, c1)");
        }
        lbcrypto::DCRTPoly c0 = elements[0];
        lbcrypto::DCRTPoly c1 = elements[1];
        
        // [B-2] Send c1 to Party C
        std::ostringstream c1_oss;
        lbcrypto::Serial::Serialize(c1, c1_oss, lbcrypto::SerType::BINARY);
        mpc_network_io_->sendString(c1_oss.str());
        std::cout << "[DistributedDecryption] Party B: Sent c1 to Party C" << std::endl;
        
        // [B-3] Receive masked value from Party C
        std::string masked_str = mpc_network_io_->recvString();
        std::istringstream masked_iss(masked_str);
        lbcrypto::DCRTPoly masked_val_from_C;
        lbcrypto::Serial::Deserialize(masked_val_from_C, masked_iss, lbcrypto::SerType::BINARY);
        std::cout << "[DistributedDecryption] Party B: Received masked value from Party C" << std::endl;
        
        // [B-4] Compute Share_B = (c0 + c1 * s_B) + masked_val_from_C
        const lbcrypto::DCRTPoly& s_B = my_secret_key_share_->GetPrivateElement();
        lbcrypto::DCRTPoly partial_B = c1 * s_B;
        lbcrypto::DCRTPoly val_B = c0 + partial_B;
        lbcrypto::DCRTPoly share_B_poly = val_B + masked_val_from_C;
        
        std::cout << "[DistributedDecryption] Party B: Computed MPC Share_B" << std::endl;
        
        // Return Share_B and empty Share_C (Party C holds its own share)
        lbcrypto::DCRTPoly empty_share_C;
        return {share_B_poly, empty_share_C};
        
    } 
    // -----------------------------------------------------------------
    // Role: Party C (Helper)
    // -----------------------------------------------------------------
    else if (party == 3) {
        std::cout << "[DistributedDecryption] Party C: Starting distributed decryption protocol..." << std::endl;
        
        // [C-1] Receive c1 from Party B
        std::string c1_str = mpc_network_io_->recvString();
        std::istringstream c1_iss(c1_str);
        lbcrypto::DCRTPoly c1;
        lbcrypto::Serial::Deserialize(c1, c1_iss, lbcrypto::SerType::BINARY);
        std::cout << "[DistributedDecryption] Party C: Received c1 from Party B" << std::endl;
        
        // [C-2] Generate random Share_C (Uniform Random Polynomial in R_q)
        auto params = cc_from_party_A_->GetElementParams();
        using DugType = typename lbcrypto::DCRTPoly::DugType;
        DugType dug;
        lbcrypto::DCRTPoly share_C_poly(dug, params, Format::EVALUATION);
        
        // [C-3] Compute masked value: Masked_C = (c1 * s_C) - Share_C
        const lbcrypto::DCRTPoly& s_C = my_secret_key_share_->GetPrivateElement();
        lbcrypto::DCRTPoly partial_C = c1 * s_C;
        lbcrypto::DCRTPoly masked_val = partial_C - share_C_poly;
        
        // [C-4] Send masked value to Party B
        std::ostringstream masked_oss;
        lbcrypto::Serial::Serialize(masked_val, masked_oss, lbcrypto::SerType::BINARY);
        mpc_network_io_->sendString(masked_oss.str());
        std::cout << "[DistributedDecryption] Party C: Sent masked value to Party B" << std::endl;
        std::cout << "[DistributedDecryption] Party C: Computed MPC Share_C" << std::endl;
        
        // Return empty Share_B and Share_C (Party B holds its own share)
        lbcrypto::DCRTPoly empty_share_B;
        return {empty_share_B, share_C_poly};
    }
    
    // Should never reach here
    throw std::runtime_error("RunDistributedDecryptionProtocol: Invalid party");
}
