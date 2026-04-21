#ifndef VAULTDB_FHE_PREDICATE_TYPES_H_
#define VAULTDB_FHE_PREDICATE_TYPES_H_

#include "openfhe.h"
#include <map>
#include <string>
#include <vector>

namespace vaultdb {

/// Encrypted predicate received from Party A: radix-encoded digits + strategy.
/// Used by Party B when parsing FheFilter from plan.
/// digits = channel 0 only (backward compat). digits_per_channel[ch][d] = digit d in channel ch (for multi-channel SUM).
struct EncryptedPredicate {
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> digits;
  /// Per-channel digits for multi-channel filter (e.g. SUM); empty = single-channel only.
  std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> digits_per_channel;
  size_t radix_base = 8;
  size_t num_digits = 4;
};

using EncryptedPredicatesMap = std::map<std::string, EncryptedPredicate>;

}  // namespace vaultdb

#endif  // VAULTDB_FHE_PREDICATE_TYPES_H_
