#ifndef UTIL_GOOGLE_TEST_FLAGS_H
#define UTIL_GOOGLE_TEST_FLAGS_H

#include <gflags/gflags.h>

// Common (MPC/FHE shared)
DECLARE_string(unioned_db);
DECLARE_int32(cutoff);
DECLARE_bool(validation);
DECLARE_string(filter);

// Network / party (MPC 2-party)
DECLARE_int32(party);
DECLARE_int32(port);
DECLARE_string(alice_host);
DECLARE_string(alice_db);
DECLARE_string(bob_db);
DECLARE_int32(ctrl_port);
DECLARE_string(storage);

// Network / party (FHE 3-party)
DECLARE_int32(fhe_party);
DECLARE_int32(fhe_port);
DECLARE_int32(fhe_charlie_port);
DECLARE_int32(fhe_mpc_port);
DECLARE_string(fhe_bob_host);
DECLARE_string(fhe_charlie_host);
DECLARE_int32(fhe_mpc_in_circuit_port);

// Execution options
DECLARE_string(server_profile);
DECLARE_bool(fhe_single_party);
DECLARE_bool(fhe_cmp_stats);
DECLARE_bool(fhe_mpc_debug_masked_decrypt);
DECLARE_bool(fhe_decryption_in_mpc);
DECLARE_bool(debug);

// Paper experiment controls
DECLARE_bool(fhe_force_baseline);
DECLARE_int32(fhe_force_threads);
DECLARE_int32(fhe_force_ring_dim);
DECLARE_int32(fhe_force_mult_depth);
DECLARE_bool(all_column_encrypt);
DECLARE_int32(sort_limit);
DECLARE_string(fhe_plan_path_override);
DECLARE_bool(fhe_gpu);

#endif  // UTIL_GOOGLE_TEST_FLAGS_H
