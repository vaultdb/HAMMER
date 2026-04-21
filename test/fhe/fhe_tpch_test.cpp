#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <omp.h>

#include <test/fhe/fhe_base_test.h>
#include <test/support/tpch_queries.h>
#include <parser/plan_parser.h>
#include <operators/columnar/column_operator.h>
#include <operators/columnar/mpc_hosting_operator.h>
#include <operators/columnar/secure_context_switch.h>
#include <query_table/columnar/fhe_column_table.h>
#include <query_table/query_schema.h>
#include <query_table/query_table.h>
#include <util/crypto_manager/fhe_manager.h>
#include <util/utilities.h>
#include <util/fhe/fhe_thread_cost_model.h>
#include <util/system_configuration.h>
#include <util/fhe/fhe_helpers.h>
#include <util/fhe/fhe_mpc_party_a.h>
#include <util/fhe/fhe_mpc_party_b.h>
#include <util/fhe/fhe_mpc_party_c.h>
#include <util/fhe/fhe_network.h>
#include <util/dictionary_manager.h>
#include <util/google_test_flags.h>
#include <operators/columnar/fhe_filter.h>

using namespace lbcrypto;
using namespace vaultdb;

namespace {
std::string getDictionaryPathForPlan(const std::string& test_name) {
    std::string base = Utilities::getCurrentWorkingDirectory() + "/conf/plans/fhe/";
    // Check override path first (for E4 base ablation experiments)
    const std::string& override_path = FLAGS_fhe_plan_path_override;
    if (!override_path.empty()) {
        if (override_path.find("base2") != std::string::npos) return base + "tpch_metadata_dictionary_base2.json";
        if (override_path.find("base4") != std::string::npos) return base + "tpch_metadata_dictionary_base4.json";
        if (override_path.find("base16") != std::string::npos) return base + "tpch_metadata_dictionary_base16.json";
        if (override_path.find("base64") != std::string::npos) return base + "tpch_metadata_dictionary_base64.json";
    }
    if (test_name == "q1_base16") return base + "tpch_metadata_dictionary_base16.json";
    if (test_name == "q1_base4") return base + "tpch_metadata_dictionary_base4.json";
    return base + "tpch_metadata_dictionary.json";
}

SecureContextSwitch* findSecureContextSwitchOp(Operator<emp::Bit>* op) {
    if (!op) return nullptr;
    if (auto* scs = dynamic_cast<SecureContextSwitch*>(op)) return scs;
    if (auto* left = findSecureContextSwitchOp(op->getChild(0))) return left;
    return findSecureContextSwitchOp(op->getChild(1));
}
}  // namespace

// =============================================================================
// FHE-only vs MPC flow (unified in runTest):
// - Party A: Always connects to B and C in SetUp. Receives result_mode from B first.
//   MPC (1): CollectSharesAndReconstruct from B+C, prints filtered by dummy_tag==0.
//   FHE-only (0): receiveResultTable from B only, prints filtered by dummy_tag>0.
// - Party B: If plan has MpcHostingOperator (SecureContextSwitch), connects to C and runs MPC.
//   Else (FHE-only): sends no-MPC termination to C, sends encrypted table to A.
// - Party C: If plan has no MpcHostingOperator, exits early (never waits for B).
//   If has MpcHostingOperator: SecureContextSwitch waits for B on mpc_port; recv no-MPC to exit.
// =============================================================================

// Flags from util/google_test_flags.cpp (via fhe_base_test.h)
class FheTpchTest : public FheBaseTest {
protected:
    void runTest(const int& test_id, const string& test_name);
    void sendPredicates() override;
    int input_tuple_limit_ = -1;
    std::vector<PredicateDef> current_test_predicates_;
    std::string masked_ct_debug_serialized_;
};

void FheTpchTest::sendPredicates() {
    sendPredicatesFromVector(current_test_predicates_);
}

void FheTpchTest::runTest(const int& test_id, const string& test_name) {
    using namespace std::chrono;
    SystemConfiguration& s = SystemConfiguration::getInstance();

    // --sort_limit bounds input rows via SQL LIMIT at scan time
    if (FLAGS_sort_limit > 0) {
        input_tuple_limit_ = FLAGS_sort_limit;
    }

    std::string plan_file;
    if (!FLAGS_fhe_plan_path_override.empty()) {
        plan_file = FLAGS_fhe_plan_path_override;
        std::cout << "[FheTpchTest] PLAN_PATH OVERRIDE: " << plan_file << std::endl;
    } else {
        plan_file = Utilities::getCurrentWorkingDirectory() + "/conf/plans/fhe/" + test_name + ".json";
    }

    if (s.party_ == 1) {
        DictionaryManager::getInstance().load(getDictionaryPathForPlan(test_name));
        sendPredicates();
        if (FLAGS_debug) std::cout << "[FheTpchTest] Party A: predicates sent, waiting for result-mode header from B..." << std::endl;
        int32_t result_mode = -1;
        network_io_->recvData(&result_mode, sizeof(int32_t));

        // Party A: Branch on result_mode. MPC => wait for B and C shares. FHE-only => receive from B only (no C).
        std::unique_ptr<MpcReconstructedRowData> row_data;
        if (result_mode == kResultModeMpcRowShares) {
            if (FLAGS_debug) std::cout << "[FheTpchTest] Party A: mode MPC (1). Collecting shares from B and C." << std::endl;
            row_data = CollectSharesAndReconstruct(network_io_.get(), getCharlieNetworkIO(), FLAGS_validation);
            if (row_data) PrintPartyAResultTable(row_data.get(), true);
        } else if (result_mode == kResultModeFheColumnar) {
            // Step 3: FHE-only plan (no SecureContextSwitch). B sent encrypted table; A decrypts only (no C).
            if (FLAGS_debug) std::cout << "[FheTpchTest] Party A: mode FHE (0). FHE-only — receiving encrypted table from B, decrypting (no C)." << std::endl;
            std::shared_ptr<FheColumnTable> fhe_table = receiveResultTable();
            row_data = ConvertFheTableToRowData(fhe_table, FheManager::getInstance());
            PrintPartyAResultTable(row_data.get(), false);
        } else {
            throw std::runtime_error("[FheTpchTest] Party A: unknown result mode: " + std::to_string(result_mode));
        }

        if (FLAGS_validation && row_data && test_id >= 0) {
            std::string unioned_db = FLAGS_unioned_db.empty() ? "tpch_unioned_150" : FLAGS_unioned_db;
            std::string expected_query = generateExpectedOutputQuery(test_id, unioned_db);
            bool is_mpc = (result_mode == kResultModeMpcRowShares);
            ValidateTpchPartyAResultsFromRowData(row_data.get(), unioned_db, expected_query, 2, is_mpc);
        }
        return;
    }

    // Party C: Only used when plan has SecureContextSwitch (MPC path). For FHE-only plans, exit early.
    // If no MpcHostingOperator: C never waits for B's MPC handover; B's no-MPC signal is irrelevant.
    // If has MpcHostingOperator: C runs SecureContextSwitch which waits for B on mpc_port.
    if (s.party_ == 3) {
        PlanParser<void>::setPartyACryptoContext(getPartyACryptoContext());
        PlanParser<void>::setPartyAPublicKey(getPartyAPublicKey());
        PlanParser<void>::setPartySecretKeyShare(my_secret_key_share_);

        PlanParser<void> parser(db_name_, plan_file, input_tuple_limit_, true);
        Operator<void>* root = parser.getRoot();
        if (!root) throw std::runtime_error("[FheTpchTest] Party C: plan parser returned null root");

        ColumnOperator<void>* col_op = reinterpret_cast<ColumnOperator<void>*>(root);
        auto* host = dynamic_cast<MpcHostingOperator*>(col_op);
        if (!host) {
            if (FLAGS_debug) std::cout << "[FheTpchTest] Party C: no MPC suffix in plan, exiting." << std::endl;
            return;
        }

        // Party C executes only the MPC suffix (SecureContextSwitch + downstream MPC ops).
        Operator<emp::Bit>* mpc_root = host->getRealMpcOp();
        if (!mpc_root) throw std::runtime_error("[FheTpchTest] Party C: real MPC root is null");
        QueryTable<emp::Bit>* mpc_result = mpc_root->run();
        if (!mpc_result) throw std::runtime_error("[FheTpchTest] Party C: MPC root run returned null");
        SecureTable* final_table = reinterpret_cast<SecureTable*>(mpc_result);
        if (!final_table) throw std::runtime_error("[FheTpchTest] Party C: run result is null");

        // Keep lockstep with Party B before sending shares to Party A.
        auto* scs = findSecureContextSwitchOp(mpc_root);
        if (scs && scs->getMpcNetworkIO()) {
            char sync_byte = 0;
            scs->getMpcNetworkIO()->recvData(&sync_byte, 1);
            scs->getMpcNetworkIO()->sendData(&sync_byte, 1);
        }

        std::vector<int64_t> flat_shares = extractAllLocalShares(final_table);
        size_t share_count = flat_shares.size();
        network_io_->sendData(&share_count, sizeof(size_t));
        if (share_count > 0) {
            network_io_->sendData(flat_shares.data(), share_count * sizeof(int64_t));
        }
        return;
    }

    if (s.party_ != 2) {
        throw std::runtime_error("Invalid party: must be 1 (A), 2 (B), or 3 (C)");
    }

    PlanParser<void>::setEncryptedPredicatesMap(&getEncryptedPredicates());
    PlanParser<void>::setPartyACryptoContext(getPartyACryptoContext());
    PlanParser<void>::setPartyAPublicKey(getPartyAPublicKey());
    PlanParser<void>::setPartySecretKeyShare(my_secret_key_share_);
    std::cout << "[FheTpchTest] Party B: " << getEncryptedPredicates().size() << " predicate(s), plan=" << plan_file << std::endl;
    if (FLAGS_debug) {
        auto& map = getEncryptedPredicates();
        std::cout << "[Debug] Encrypted predicates map size: " << map.size() << std::endl;
        for (auto& pair : map) {
            std::cout << "[Debug] Key: " << pair.first << ", Channels: " << pair.second.digits_per_channel.size() << std::endl;
        }
    }
    {
        const char* omp_num = std::getenv("OMP_NUM_THREADS");
        std::cout << "[OpenMP] max_threads=" << omp_get_max_threads()
                  << " num_procs=" << omp_get_num_procs()
                  << " OMP_NUM_THREADS=" << (omp_num ? omp_num : "unset")
                  << std::endl;
    }

    size_t initial_memory = Utilities::checkMemoryUtilization(true);
    time_point<high_resolution_clock> startTime = high_resolution_clock::now();

    PlanParser<void> parser(db_name_, plan_file, input_tuple_limit_, true);
    Operator<void>* root = parser.getRoot();
    if (!root) throw std::runtime_error("FheTpchTest: plan parser returned null root");

    // Party B: Branch on plan type. host => MPC path (connects to C, runs SecureContextSwitch).
    // !host => FHE-only path (no C connection; sends no-MPC signal so C can exit if it was waiting).
    ColumnOperator<void>* col_op = reinterpret_cast<ColumnOperator<void>*>(root);
    auto* host = dynamic_cast<MpcHostingOperator*>(col_op);
    if (host) {
        // MPC path: Connect to C (inside SecureContextSwitch), run, send shares to A, sync with C.
        auto result_ptr = host->runSelf();
        if (!result_ptr) throw std::runtime_error("[FheTpchTest] Party B: root run returned null");
        SecureTable* sorted_table = reinterpret_cast<SecureTable*>(result_ptr.get());
        if (!sorted_table) throw std::runtime_error("[FheTpchTest] Party B: run result is null");

        auto endTime = high_resolution_clock::now();
        double duration = duration_cast<microseconds>(endTime - startTime).count() / 1e6;
        std::cout << "[FheTpchTest] Runtime: " << duration << " sec" << std::endl;
        size_t peak_memory = Utilities::checkMemoryUtilization(true);
        std::cout << "[FheTpchTest] Party B: Memory usage: " << (peak_memory - initial_memory) << " bytes" << std::endl;

        if (FLAGS_fhe_cmp_stats) {
            auto stats = vaultdb::getPolynomialComparisonStats();
            vaultdb::printComparatorStats(stats, "Q1 Filter (Polynomial)");
        }
        if (SystemConfiguration::getInstance().hasMpc()) {
            SystemConfiguration::getInstance().mpc()->flush();
        }
        Operator<emp::Bit>* mpc_root = host->getRealMpcOp();
        auto* scs = findSecureContextSwitchOp(mpc_root);
        SyncWithPartyC(host);

        SendResultModeHeader(network_io_.get(), kResultModeMpcRowShares);
        std::vector<int64_t> flat_shares = extractAllLocalShares(sorted_table);
        const QuerySchema* display_schema = scs ? scs->getDisplaySchemaForPartyA() : nullptr;
        SendSharesToPartyA(sorted_table, network_io_.get(), display_schema, &flat_shares);
    } else {
        // Step 2: FHE-only path (no SecureContextSwitch). B runs to FheColumnTable, sends encrypted table to A; A decrypts. No C.
        // col_op already set above (root is ColumnOperator but not MpcHostingOperator).
        auto result_ptr = col_op->runSelf();
        if (!result_ptr) throw std::runtime_error("[FheTpchTest] Party B: FHE-only root run returned null");
        auto fhe_table = std::dynamic_pointer_cast<FheColumnTable>(result_ptr);
        if (!fhe_table) throw std::runtime_error("[FheTpchTest] Party B: FHE-only root did not return FheColumnTable");

        auto endTime = high_resolution_clock::now();
        double duration = duration_cast<microseconds>(endTime - startTime).count() / 1e6;
        std::cout << "[FheTpchTest] Runtime (FHE-only): " << duration << " sec" << std::endl;
        size_t peak_memory = Utilities::checkMemoryUtilization(true);
        std::cout << "[FheTpchTest] Party B: Memory usage: " << (peak_memory - initial_memory) << " bytes" << std::endl;
        if (FLAGS_fhe_cmp_stats) {
            auto stats = vaultdb::getPolynomialComparisonStats();
            vaultdb::printComparatorStats(stats, "Q1 Filter (Polynomial)");
        }

        SendResultModeHeader(network_io_.get(), kResultModeFheColumnar);
        sendResultTable(fhe_table);
        // FHE-only: No C connection. Send no-MPC signal so C (if running) can exit handover wait.
        try {
            int mpc_port = (FLAGS_fhe_mpc_port > 0) ? FLAGS_fhe_mpc_port : 8777;
            std::string charlie_host = FLAGS_fhe_charlie_host.empty() ? "127.0.0.1" : FLAGS_fhe_charlie_host;
            FheNetworkIO to_party_c(charlie_host, mpc_port, false);
            size_t no_mpc_marker = std::numeric_limits<size_t>::max();
            to_party_c.sendData(&no_mpc_marker, sizeof(size_t));
            if (FLAGS_debug) std::cout << "[FheTpchTest] Party B: Sent no-MPC termination signal to Party C." << std::endl;
        } catch (const std::exception& e) {
            if (FLAGS_debug) std::cout << "[FheTpchTest] Party B: Failed to notify Party C (continuing): " << e.what() << std::endl;
        }
    }
    std::fflush(stdout);
    /* Return normally so TearDown runs and next test can use fresh SetUp (listen again) */
}

// Sort-only plan (sorting_lineitem): FheTableScan -> SecureContextSwitch -> LogicalSort.
// Keep predicates empty unless the JSON includes FheFilter.
TEST_F(FheTpchTest, fhe_tpch_sort_lineitem) {
    current_test_predicates_ = {};
    runTest(-1, "sorting_lineitem");
}

// AVG is intentionally pushed to MPC LogicalProject (after SecureContextSwitch).
TEST_F(FheTpchTest, fhe_tpch_q1) {
    current_test_predicates_ = {
            buildPredicateDefFromSQL("lineitem", "l_shipdate", "less_equal", "1998-08-03")
    };
    runTest(1, "q1");
}

// Simplified Q1 plan with single SUM aggregate (l_returnflag, l_linestatus, sum_qty only)
TEST_F(FheTpchTest, fhe_tpch_q1_one_sum) {
    current_test_predicates_ = {
            buildPredicateDefFromSQL("lineitem", "l_shipdate", "less_equal", "1998-08-03")
    };
    runTest(-1, "q1_one_sum");  // -1: skip validation (plan differs from full Q1)
}

// Experiment: Base 4 (degree 6, 6 digits)
// TEST_F(FheTpchTest, fhe_tpch_q1_base4) {
//     current_test_predicates_ = {
//             buildPredicateDefFromSQL("lineitem", "l_shipdate", "less_equal", "1998-08-03")
//     };
//     runTest(1, "q1_base4");
// }

// Experiment: Base 16 (degree 30, 3 digits)
// TEST_F(FheTpchTest, fhe_tpch_q1_base16) {
//     current_test_predicates_ = {
//             buildPredicateDefFromSQL("lineitem", "l_shipdate", "less_equal", "1998-08-03")
//     };
//     runTest(1, "q1_base16");
// }

// Radix experiment: run with --filter=*fhe_tpch_q1_base60* (or base16/base4)
//   ./bin/fhe_tpch_test --party=2 --filter=*fhe_tpch_q1_base60* --unioned_db=tpch_unioned_150
//   ./bin/fhe_tpch_test --party=3 --filter=*fhe_tpch_q1_base60* --unioned_db=tpch_unioned_150
//   ./bin/fhe_tpch_test --party=1 --filter=*fhe_tpch_q1_base60* --unioned_db=tpch_unioned_150
// TEST_F(FheTpchTest, fhe_tpch_q1_base60) {
//     current_test_predicates_ = {
//         buildPredicateDefFromSQL("lineitem", "l_shipdate", "less_equal", "1998-08-03")
//     };
//     runTest(1, "q1_base60");
// }


// Test Q3: c_mktsegment = [SEGMENT], o_orderdate < [DATE], l_shipdate > [DATE] (TPC-H Q3 uses HOUSEHOLD, 1995-03-25)
TEST_F(FheTpchTest, fhe_tpch_q3) {
   current_test_predicates_ = {
       buildPredicateDefFromSQL("customer", "c_mktsegment", "equal", "HOUSEHOLD", "c_mktsegment"),
       buildPredicateDefFromSQL("orders", "o_orderdate", "less_than", "1995-03-25", "o_orderdate_less_than"),
       buildPredicateDefFromSQL("lineitem", "l_shipdate", "greater_than", "1995-03-25", "l_shipdate_greater_than")
   };
   runTest(3, "q3");
}

// Test Q5: COUNT with r_name = 'EUROPE' and date range filter
TEST_F(FheTpchTest, fhe_tpch_q5) {
    current_test_predicates_ = {
        buildPredicateDefFromSQL("region", "r_name", "equal", "EUROPE", "r_name"),
        buildPredicateDefFromSQL("orders", "o_orderdate", "greater_equal", "1993-01-01", "o_orderdate_greater_equal"),
        buildPredicateDefFromSQL("orders", "o_orderdate", "less_than", "1994-01-01", "o_orderdate_less_than")
    };
    runTest(5, "q5");
}

// Test Q6: global SUM(l_extendedprice * l_discount) with date/discount/quantity range filters (single table, one group)
TEST_F(FheTpchTest, fhe_tpch_q6) {
    current_test_predicates_ = {
        buildPredicateDefFromSQL("lineitem", "l_shipdate", "greater_equal", "1997-01-01", "l_shipdate_greater_equal"),
        buildPredicateDefFromSQL("lineitem", "l_shipdate", "less_than", "1998-01-01", "l_shipdate_less_than"),
        buildPredicateDefFromSQL("lineitem", "l_discount", "greater_equal", "0.02", "l_discount_greater_equal"),
        buildPredicateDefFromSQL("lineitem", "l_discount", "less_equal", "0.04", "l_discount_less_equal"),
        buildPredicateDefFromSQL("lineitem", "l_quantity", "less_than", "24", "l_quantity_less_than")
    };
    runTest(6, "q6");
}

// Test Q12: l_shipmode IN ('TRUCK', 'AIR REG') + date range on l_receiptdate
// Party A sends each IN value as a separate encrypted predicate with indexed wire keys (_in_0, _in_1).
// The parser expands JSON "type":"in" into N equal entries sharing the same OR group;
// FheFilter combines them via EvalAdd (OR, depth 0) then ANDs with other predicates.
TEST_F(FheTpchTest, fhe_tpch_q12) {
    current_test_predicates_ = {
        buildPredicateDefFromSQL("lineitem", "l_shipmode", "equal", "TRUCK", "l_shipmode_in_0"),
        buildPredicateDefFromSQL("lineitem", "l_shipmode", "equal", "AIR REG", "l_shipmode_in_1"),
        buildPredicateDefFromSQL("lineitem", "l_receiptdate", "greater_equal", "1994-01-01", "l_receiptdate_greater_equal"),
        buildPredicateDefFromSQL("lineitem", "l_receiptdate", "less_than", "1995-01-01", "l_receiptdate_less_than")
    };
    runTest(12, "q12");
}

// Test Q4: order priority count (orders + lineitem), date range on o_orderdate
TEST_F(FheTpchTest, fhe_tpch_q4) {
    current_test_predicates_ = {
        buildPredicateDefFromSQL("orders", "o_orderdate", "greater_equal", "1993-07-01", "o_orderdate_greater_equal"),
        buildPredicateDefFromSQL("orders", "o_orderdate", "less_than", "1993-10-01", "o_orderdate_less_than")
    };
    runTest(4, "q4");
}

// Test Q7: nation pair revenue (supplier, lineitem, orders, customer, nation x2), one nation pair + l_shipdate range
TEST_F(FheTpchTest, fhe_tpch_q7) {
    current_test_predicates_ = {
        buildPredicateDefFromSQL("nation", "n_name", "equal", "UNITED STATES", "n1_name"),
        buildPredicateDefFromSQL("nation", "n_name", "equal", "EGYPT", "n2_name"),
        buildPredicateDefFromSQL("lineitem", "l_shipdate", "greater_equal", "1995-01-01", "l_shipdate_greater_equal"),
        buildPredicateDefFromSQL("lineitem", "l_shipdate", "less_than", "1996-12-31", "l_shipdate_less_than")
    };
    runTest(7, "q7");
}

// Test Q8: market share (part, lineitem, supplier, orders, customer, nation, region), r_name + date + p_type
TEST_F(FheTpchTest, fhe_tpch_q8) {
    current_test_predicates_ = {
        buildPredicateDefFromSQL("region", "r_name", "equal", "AFRICA", "r_name"),
        buildPredicateDefFromSQL("orders", "o_orderdate", "greater_equal", "1995-01-01", "o_orderdate_greater_equal"),
        buildPredicateDefFromSQL("orders", "o_orderdate", "less_than", "1996-12-31", "o_orderdate_less_than"),
        buildPredicateDefFromSQL("part", "p_type", "equal", "LARGE ANODIZED STEEL", "p_type")
    };
    runTest(8, "q8");
}

// Test Q10: customer revenue (customer, orders, lineitem, nation), o_orderdate range + l_returnflag = 'R'
TEST_F(FheTpchTest, fhe_tpch_q10) {
    current_test_predicates_ = {
        buildPredicateDefFromSQL("orders", "o_orderdate", "greater_equal", "1994-03-01", "o_orderdate_greater_equal"),
        buildPredicateDefFromSQL("orders", "o_orderdate", "less_than", "1994-06-01", "o_orderdate_less_than"),
        buildPredicateDefFromSQL("lineitem", "l_returnflag", "equal", "R", "l_returnflag")
    };
    runTest(10, "q10");
}

// Test Q19: DNF (OR-of-AND) predicate structure:
//   Common: l_shipinstruct='DELIVER IN PERSON', l_shipmode IN ('AIR','AIR REG'), p_size >= 1
//   Group 0: Brand#41, SM containers, l_quantity [2,12], p_size <= 5
//   Group 1: Brand#13, MED containers, l_quantity [14,24], p_size <= 10
//   Group 2: Brand#55, LG containers, l_quantity [23,33], p_size <= 15
//   Result = common AND (group0 OR group1 OR group2)
TEST_F(FheTpchTest, fhe_tpch_q19) {
    current_test_predicates_ = {
        // Common predicates
        buildPredicateDefFromSQL("lineitem", "l_shipinstruct", "equal", "DELIVER IN PERSON", "l_shipinstruct"),
        buildPredicateDefFromSQL("lineitem", "l_shipmode", "equal", "AIR", "l_shipmode_in_0"),
        buildPredicateDefFromSQL("lineitem", "l_shipmode", "equal", "AIR REG", "l_shipmode_in_1"),
        buildPredicateDefFromSQL("part", "p_size", "greater_equal", "1", "p_size_greater_equal"),
        // Group 0: Brand#41, SM containers, l_quantity [2,12], p_size <= 5
        buildPredicateDefFromSQL("part", "p_brand", "equal", "Brand#41", "p_brand_0"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "SM CASE", "p_container_0_in_0"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "SM BOX", "p_container_0_in_1"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "SM PACK", "p_container_0_in_2"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "SM PKG", "p_container_0_in_3"),
        buildPredicateDefFromSQL("lineitem", "l_quantity", "greater_equal", "2", "l_quantity_0_greater_equal"),
        buildPredicateDefFromSQL("lineitem", "l_quantity", "less_equal", "12", "l_quantity_0_less_equal"),
        buildPredicateDefFromSQL("part", "p_size", "less_equal", "5", "p_size_0_less_equal"),
        // Group 1: Brand#13, MED containers, l_quantity [14,24], p_size <= 10
        buildPredicateDefFromSQL("part", "p_brand", "equal", "Brand#13", "p_brand_1"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "MED BAG", "p_container_1_in_0"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "MED BOX", "p_container_1_in_1"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "MED PKG", "p_container_1_in_2"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "MED PACK", "p_container_1_in_3"),
        buildPredicateDefFromSQL("lineitem", "l_quantity", "greater_equal", "14", "l_quantity_1_greater_equal"),
        buildPredicateDefFromSQL("lineitem", "l_quantity", "less_equal", "24", "l_quantity_1_less_equal"),
        buildPredicateDefFromSQL("part", "p_size", "less_equal", "10", "p_size_1_less_equal"),
        // Group 2: Brand#55, LG containers, l_quantity [23,33], p_size <= 15
        buildPredicateDefFromSQL("part", "p_brand", "equal", "Brand#55", "p_brand_2"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "LG CASE", "p_container_2_in_0"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "LG BOX", "p_container_2_in_1"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "LG PACK", "p_container_2_in_2"),
        buildPredicateDefFromSQL("part", "p_container", "equal", "LG PKG", "p_container_2_in_3"),
        buildPredicateDefFromSQL("lineitem", "l_quantity", "greater_equal", "23", "l_quantity_2_greater_equal"),
        buildPredicateDefFromSQL("lineitem", "l_quantity", "less_equal", "33", "l_quantity_2_less_equal"),
        buildPredicateDefFromSQL("part", "p_size", "less_equal", "15", "p_size_2_less_equal")
    };
    runTest(19, "q19");
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    vaultdb::setComparatorStatsEnabled(FLAGS_fhe_cmp_stats);
    if (!FLAGS_server_profile.empty()) {
        vaultdb::initServerProfile(FLAGS_server_profile);
    }
    ::testing::GTEST_FLAG(filter) = FLAGS_filter;
    int i = RUN_ALL_TESTS();
    google::ShutDownCommandLineFlags();
    return i;
}

