#ifndef _FHE_HELPERS_H_
#define _FHE_HELPERS_H_

#include <cstdint>
#include <string>
#include <vector>

#include "openfhe.h"
#include "query_table/field/field.h"
#include "query_table/query_table.h"
#include "query_table/columnar/column_table_base.h"

namespace vaultdb {

int64_t relativeDaysFromDateString(const std::string& date_str);
std::vector<int64_t> encodeRadixDigits(int64_t value, size_t radix_base, size_t num_digits);
int64_t getInt64FromField(const PlainField& field);

/// Build a PlainField from int64 for use in reconstructed MPC result tables (INT/LONG/DATE/BOOL).
PlainField makePlainFieldFromInt64(int64_t value, FieldType type);

/// CRT combine: given residues[i] mod moduli[i], returns v such that v ≡ residues[i] (mod moduli[i]).
/// Uses first moduli.size() elements; result may exceed int64_t for 4 moduli (then reduced mod 2^63).
int64_t CrtCombine(const std::vector<uint64_t>& residues, const std::vector<uint64_t>& moduli);

/// 3-prime RNS modulus: 1179649 * 2752513 * 8519681 (~64.6 bits). Use for modular reduction after
/// MPC reveal so that (R + (M-R)) is reduced to [0, P_TOTAL_3PRIME) when the sum overflows.
constexpr uint64_t P_TOTAL_3PRIME = 1179649ULL * 2752513ULL * 8519681ULL;

/// Reduce a revealed value to [0, P_TOTAL_3PRIME). Call after reveal when the value is from
/// FHE-MPC aggregate (Secure_Sum = R + (M-R)); raw may be >= P_TOTAL due to 64-bit wrap.
int64_t ReduceModPTotal(int64_t raw_value);

std::vector<int64_t> DecodePackedValuesFromPoly(
    const lbcrypto::DCRTPoly& poly,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc);
std::vector<int64_t> DecodePackedValuesFromNativePoly(
    const lbcrypto::NativePoly& poly,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc);
std::vector<int64_t> ExtractPolyValues(const lbcrypto::Poly& poly);
std::vector<int64_t> ExtractPolyValues(const lbcrypto::NativePoly& poly);

/// Extract local bit shares from MPC SecureTable, column-major [Col0_Row0, Col0_Row1, ...].
/// Reads .bit directly (no reveal()) to avoid network.
std::vector<int64_t> extractAllLocalShares(SecureTable* table);

/// Extract additive shares for Party A reconstruction: B gets S_B, C gets S_C = M - S_B
/// via masking and reveal(BOB). Must be called by both B (party_id=2) and C (party_id=3)
/// in sync over the same sorted table; returns column-major flat shares.
std::vector<int64_t> extractAdditiveShares(SecureTable* table, int party_id);

/// Debug: print a plain table (e.g. from SecureTable::reveal(ALICE)) to stdout.
void PrintPlainTable(PlainTable* table);

/// ETL: Convert enum (string) columns to integer IDs using DictionaryManager::registerOrLookup.
/// Replaces each string value with its dict ID. New values are registered and persisted.
/// \param table PlainColumnTable to modify in place
/// \param table_name e.g. "lineitem" for Dict lookup
/// \param enum_columns e.g. {"l_shipmode", "l_returnflag"}
void convertEnumColumnsToIds(PlainColumnTable& table, const std::string& table_name,
                             const std::vector<std::string>& enum_columns);

/// ETL: Convert decimal (FLOAT) columns to scaled int64 using DictionaryManager scale_factor.
/// For FHE filter: l_discount 0.05 -> 5 (scale 100), l_tax 0.02 -> 2.
/// \param table PlainColumnTable to modify in place
/// \param table_name e.g. "lineitem" for Dict lookup
/// \param decimal_columns e.g. {"l_discount", "l_tax"}
void convertDecimalColumnsToScaledInt(PlainColumnTable& table, const std::string& table_name,
                                      const std::vector<std::string>& decimal_columns);

}  // namespace vaultdb

#endif // _FHE_HELPERS_H_
