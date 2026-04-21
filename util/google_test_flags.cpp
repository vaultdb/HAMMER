// Centralized gflags for Google Test binaries (FHE, MPC). In util/ for shared access.
#include <gflags/gflags.h>

// Common (MPC/FHE shared)
DEFINE_string(unioned_db, "tpch_unioned_150", "unioned db name");
DEFINE_int32(cutoff, 100, "limit clause for queries; -1 = no limit (full table)");
DEFINE_bool(validation, true, "run reveal for validation");
DEFINE_string(filter, "*", "run only tests matching this filter");

// Network / party (MPC 2-party)
DEFINE_int32(party, 1, "party for EMP execution: 1=Alice, 2=Bob");
DEFINE_int32(port, 54345, "port for EMP execution");
DEFINE_string(alice_host, "127.0.0.1", "alice hostname for EMP execution");
DEFINE_string(alice_db, "tpch_alice_150", "alice db name");
DEFINE_string(bob_db, "tpch_bob_150", "bob db name");
DEFINE_int32(ctrl_port, 65455, "port for managing EMP control flow");
DEFINE_string(storage, "column", "storage model: column, wire_packed or compressed");

// Network / party (FHE 3-party)
DEFINE_int32(fhe_party, 1, "party for FHE execution: 1=Party A, 2=Party B, 3=Party C");
DEFINE_int32(fhe_port, 8765, "port for FHE network (Party B)");
DEFINE_int32(fhe_charlie_port, 8766, "port for FHE network (Party C)");
DEFINE_int32(fhe_mpc_port, 8777, "port for MPC communication between B and C");
DEFINE_string(fhe_bob_host, "127.0.0.1", "Party B hostname");
DEFINE_string(fhe_charlie_host, "127.0.0.1", "Party C hostname");
DEFINE_int32(fhe_mpc_in_circuit_port, 12345, "port for MPC in-circuit decryption");

// Execution options
DEFINE_string(server_profile, "",
    "Path to server_profile_*.json for automatic thread optimization. "
    "If empty, uses OMP_NUM_THREADS environment variable.");
DEFINE_bool(fhe_single_party, false, "single-server mode: no B/C, just local key gen (for fhe_filter_test etc)");
DEFINE_bool(fhe_cmp_stats, false, "enable detailed comparator stats");
DEFINE_bool(fhe_mpc_debug_masked_decrypt, false, "debug: send masked ciphertext to Party A");
DEFINE_bool(fhe_decryption_in_mpc, false, "use MPC in-circuit decryption");
DEFINE_bool(debug, false, "enable verbose debug output");

// Paper experiment controls
DEFINE_bool(fhe_force_baseline, false,
    "Force baseline FHE parameters: ring_dim=65536, mult_depth=15. "
    "Used for Config A in paper experiments.");
DEFINE_int32(fhe_force_threads, 0,
    "Override selectThreadCount() with this value. 0 = auto (default).");
DEFINE_int32(fhe_force_ring_dim, 0,
    "Override ring_dim (0=auto). E2/E5.");
DEFINE_int32(fhe_force_mult_depth, 0,
    "Override mult_depth (0=auto). E2/E5.");
DEFINE_bool(all_column_encrypt, false,
    "Encrypt ALL columns (Engorgio-style). E1.");
DEFINE_int32(sort_limit, 0,
    "Cap MPC sort cardinality (0=no limit). E3.");
DEFINE_string(fhe_plan_path_override, "",
    "Override plan JSON path. E4.");
DEFINE_bool(fhe_gpu, false,
    "Use GPU (HEonGPU) backend for FHE filter. E6/E7.");
