#include "util/fhe/fhe_helpers.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

#include <boost/algorithm/string/trim.hpp>
#include <openfhe/pke/encoding/packedencoding.h>

#include "common/defs.h"
#include "query_table/column_table.h"
#include "query_table/columnar/column_table_base.h"
#include "query_table/columnar/plain_column_chunk.h"
#include "query_table/field/field.h"
#include "util/dictionary_manager.h"

using namespace lbcrypto;

namespace vaultdb {
namespace {
class PackedEncodingWithSet : public PackedEncoding {
public:
    using PackedEncoding::PackedEncoding;

    void SetEncodedDCRT(const DCRTPoly& poly) {
        encodedVectorDCRT = poly;
        isEncoded = true;
    }

    void SetEncodedNative(const NativePoly& poly) {
        encodedNativeVector = poly;
        isEncoded = true;
    }
};
} // namespace

int64_t relativeDaysFromDateString(const std::string& date_str) {
    static const std::string base_date = "1992-01-01";
    auto parse_date = [](const std::string& str) {
        std::tm t{};
        int y, m, d;
        if (std::sscanf(str.c_str(), "%d-%d-%d", &y, &m, &d) != 3) {
            throw std::runtime_error("Failed to parse date string: " + str);
        }
        t.tm_year = y - 1900;
        t.tm_mon = m - 1;
        t.tm_mday = d;
        t.tm_hour = 0;
        t.tm_min = 0;
        t.tm_sec = 0;
        t.tm_isdst = -1;
        return t;
    };

    const int64_t seconds_per_day = 24 * 3600;
    const auto compute_days = [&](const std::string& str) {
        std::tm tm_copy = parse_date(str);
        return static_cast<int64_t>(mktime(&tm_copy) / seconds_per_day);
    };

    static const int64_t base_days = compute_days(base_date);
    const int64_t current_days = compute_days(date_str);
    return current_days - base_days;
}

std::vector<int64_t> encodeRadixDigits(int64_t value, size_t radix_base, size_t num_digits) {
    std::vector<int64_t> digits(num_digits, 0);
    int64_t remaining = value;
    for (size_t i = 0; i < num_digits && remaining > 0; ++i) {
        digits[i] = remaining % radix_base;
        remaining /= radix_base;
    }
    return digits;
}

int64_t getInt64FromField(const PlainField& field) {
    switch (field.getType()) {
        case FieldType::INT:
            return static_cast<int64_t>(field.getValue<int32_t>());
        case FieldType::LONG:
        case FieldType::DATE:
            return field.getValue<int64_t>();
        case FieldType::BOOL:
            return field.getValue<bool>() ? 1 : 0;
        default:
            throw std::runtime_error("Unsupported field type for int64 extraction: " +
                                     std::to_string(static_cast<int>(field.getType())));
    }
}

PlainField makePlainFieldFromInt64(int64_t value, FieldType type) {
    switch (type) {
        case FieldType::INT:
            return PlainField(FieldType::INT, static_cast<int32_t>(value));
        case FieldType::LONG:
        case FieldType::DATE:
            return PlainField(FieldType::LONG, static_cast<int64_t>(value));
        case FieldType::BOOL:
            return PlainField(FieldType::BOOL, value != 0);
        default:
            throw std::runtime_error("Unsupported field type for makePlainFieldFromInt64: " +
                                     std::to_string(static_cast<int>(type)));
    }
}

std::vector<int64_t> DecodePackedValuesFromPoly(
    const DCRTPoly& poly,
    const CryptoContext<DCRTPoly>& cc) {
    auto crypto_params = cc->GetCryptoParameters();
    auto element_params = crypto_params->GetElementParams();
    auto encoding_params = crypto_params->GetEncodingParams();

    DCRTPoly coeff_poly = poly;
    coeff_poly.SetFormat(Format::COEFFICIENT);

    auto packed_pt = std::make_shared<PackedEncodingWithSet>(element_params, encoding_params);
    packed_pt->SetEncodedDCRT(coeff_poly);
    packed_pt->Decode();
    return packed_pt->GetPackedValue();
}

std::vector<int64_t> DecodePackedValuesFromNativePoly(
    const NativePoly& poly,
    const CryptoContext<DCRTPoly>& cc) {
    auto encoding_params = cc->GetCryptoParameters()->GetEncodingParams();
    auto packed_pt = std::make_shared<PackedEncodingWithSet>(poly.GetParams(), encoding_params);
    packed_pt->SetEncodedNative(poly);
    packed_pt->Decode();
    return packed_pt->GetPackedValue();
}

std::vector<int64_t> ExtractPolyValues(const Poly& poly) {
    const auto& values = poly.GetValues();
    std::vector<int64_t> coeffs(values.GetLength());
    for (size_t i = 0; i < coeffs.size(); ++i) {
        coeffs[i] = static_cast<int64_t>(values[i].ConvertToInt());
    }
    return coeffs;
}

std::vector<int64_t> ExtractPolyValues(const NativePoly& poly) {
    const auto& values = poly.GetValues();
    std::vector<int64_t> coeffs(values.GetLength());
    for (size_t i = 0; i < coeffs.size(); ++i) {
        coeffs[i] = static_cast<int64_t>(values[i].ConvertToInt());
    }
    return coeffs;
}

namespace {
// Modular inverse of a mod m (a and m coprime).
uint64_t ModInverse(uint64_t a, uint64_t m) {
    if (m <= 1) return 0;
    int64_t t = 0, t1 = 1;
    int64_t r = static_cast<int64_t>(m), r1 = static_cast<int64_t>(a % m);
    while (r1 != 0) {
        int64_t q = r / r1;
        int64_t t0 = t; t = t1; t1 = t0 - q * t1;
        int64_t r0 = r; r = r1; r1 = r0 - q * r1;
    }
    if (r != 1) return 0;
    if (t < 0) t += static_cast<int64_t>(m);
    return static_cast<uint64_t>(t);
}
}  // namespace

// [FIXED] Correctly handles signed reconstruction via CRT (M - 1 -> -1, etc.)
int64_t CrtCombine(const std::vector<uint64_t>& residues, const std::vector<uint64_t>& moduli) {
    if (residues.size() != moduli.size() || residues.empty()) {
        throw std::runtime_error("CrtCombine: residues and moduli size must match and be non-empty");
    }
    const size_t n = residues.size();
    if (n == 1) {
        return static_cast<int64_t>(residues[0]);
    }

    // M = product of moduli; use __uint128_t
    using U128 = unsigned __int128;
    U128 M = 1;
    for (size_t i = 0; i < n; ++i) {
        if (moduli[i] == 0) throw std::runtime_error("CrtCombine: modulus 0");
        M *= moduli[i];
    }
    U128 v = 0;
    for (size_t i = 0; i < n; ++i) {
        U128 Mi = M / moduli[i];
        uint64_t yi = ModInverse(static_cast<uint64_t>(Mi % moduli[i]), moduli[i]);
        if (yi == 0) throw std::runtime_error("CrtCombine: no inverse");
        v += static_cast<U128>(residues[i] % moduli[i]) * Mi * yi;
    }
    v %= M;

    // [FIX] Correct signed handling for BFV: if v > M/2, it represents a negative number (v - M).
    if (v > (M / 2)) {
        return static_cast<int64_t>(v) - static_cast<int64_t>(M);
    }
    return static_cast<int64_t>(v);
}

int64_t ReduceModPTotal(int64_t raw_value) {
    // raw_value is often a signed view of a Z_2^64 ring value.
    // Reduce by full modulo over the raw bit pattern, not by single subtraction.
    const uint64_t u = static_cast<uint64_t>(raw_value);
    const uint64_t r = u % P_TOTAL_3PRIME;
    return static_cast<int64_t>(r);
}

std::vector<int64_t> extractAllLocalShares(SecureTable* table) {
    auto* col_table = dynamic_cast<ColumnTable<emp::Bit>*>(table);
    if (!col_table) {
        throw std::runtime_error("extractAllLocalShares: SecureTable is not a ColumnTable<emp::Bit>");
    }

    const auto& schema = table->getSchema();
    size_t row_count = table->tuple_cnt_;
    std::vector<int64_t> flat_shares;

    std::vector<int> ordinals;
    for (const auto& kv : col_table->column_data_) {
        ordinals.push_back(kv.first);
    }
    std::sort(ordinals.begin(), ordinals.end());
    flat_shares.reserve(ordinals.size() * row_count);

    for (int col_idx : ordinals) {
        int bit_width = 1;
        auto fit = schema.fields_.find(col_idx);
        if (fit != schema.fields_.end()) {
            bit_width = static_cast<int>(fit->second.size());
        } else if (col_idx == -1) {
            bit_width = 1;  // row-level dummy tag
        } else {
            throw std::runtime_error("extractAllLocalShares: schema missing ordinal " + std::to_string(col_idx));
        }
        auto cit = col_table->column_data_.find(col_idx);
        if (cit == col_table->column_data_.end()) {
            throw std::runtime_error("extractAllLocalShares: column_data_ missing key " + std::to_string(col_idx));
        }
        const std::vector<int8_t>& col_data_bytes = cit->second;
        size_t required_bytes = static_cast<size_t>(row_count * bit_width) * sizeof(emp::Bit);
        if (col_data_bytes.size() < required_bytes) {
            throw std::runtime_error("extractAllLocalShares: column " + std::to_string(col_idx) +
                " size " + std::to_string(col_data_bytes.size()) + " < " + std::to_string(required_bytes));
        }
        const emp::Bit* bits_ptr = reinterpret_cast<const emp::Bit*>(col_data_bytes.data());

        for (size_t r = 0; r < row_count; ++r) {
            int64_t val = 0;
            const emp::Bit* row_bits = bits_ptr + (r * bit_width);
            int bits_to_read = std::min(bit_width, 64);
            for (int b = 0; b < bits_to_read; ++b) {
                const emp::Bit& bit = row_bits[b];
                const uint64_t* block_ptr = reinterpret_cast<const uint64_t*>(&bit.bit);
                if (block_ptr[0] & 1ULL) val |= (1ULL << b);
            }
            flat_shares.push_back(val);
        }
    }
    return flat_shares;
}

// util/fhe/fhe_helpers.cpp
std::vector<int64_t> extractAdditiveShares(SecureTable* table, int party_id) {
    if (!table) {
        throw std::runtime_error("extractAdditiveShares: table is null");
    }
    const auto& schema = table->getSchema();
    size_t row_count = table->tuple_cnt_;
    std::vector<int64_t> flat_shares;
    const int field_count = schema.getFieldCount();

    // Iterate columns in schema order (0..field_count-1) so order matches
    // SendSharesToPartyA / CollectSharesAndReconstruct.
    for (int col_idx = 0; col_idx < field_count; ++col_idx) {
        for (size_t r = 0; r < row_count; ++r) {
            // Use the table API (getField/getInt) instead of reading raw column_data_ bytes.
            // This avoids bit-layout/stride mismatches after storage/encoding transformations.
            Field<emp::Bit> f = table->getField(static_cast<int>(r), col_idx);
            emp::Integer val = f.getInt();
            emp::Integer val_64 = val.resize(64);

            if (party_id == 2) { // Party B (Alice): s_b random, send (val - s_b) to C
                static std::mt19937_64 gen(std::random_device{}());
                int64_t s_b = static_cast<int64_t>(gen());
                emp::Integer mask(64, s_b, emp::ALICE);
                emp::Integer masked = val_64 - mask;
                masked.reveal<int64_t>(emp::BOB);
                flat_shares.push_back(s_b);
            } else { // Party C (Bob): s_c = reveal(val - s_b)
                emp::Integer mask(64, 0, emp::ALICE);
                emp::Integer masked = val_64 - mask;
                int64_t s_c = masked.reveal<int64_t>(emp::BOB);
                flat_shares.push_back(s_c);
            }
        }
    }
    return flat_shares;
}

void PrintPlainTable(PlainTable* table) {
    if (!table) {
        std::cout << "[PrintPlainTable] (null)" << std::endl;
        return;
    }
    const auto& schema = table->getSchema();
    const int field_count = schema.getFieldCount();
    const size_t row_count = table->tuple_cnt_;
    std::cout << "[B debug] Revealed sorted table: " << row_count << " rows x " << field_count << " columns" << std::endl;
    std::cout << "RowIdx\t";
    for (int c = 0; c < field_count; ++c) {
        std::cout << schema.getField(c).getName() << "\t";
    }
    std::cout << std::endl;
    auto& dm = DictionaryManager::getInstance();
    const size_t print_rows = std::min(row_count, static_cast<size_t>(20));
    for (size_t r = 0; r < print_rows; ++r) {
        std::cout << r << "\t";
        for (int c = 0; c < field_count; ++c) {
            PlainField f = table->getField(static_cast<int>(r), c);
            FieldType ft = f.getType();
            if (ft == FieldType::LONG || ft == FieldType::INT) {
                int64_t v = (ft == FieldType::INT) ? static_cast<int64_t>(f.getValue<int32_t>()) : f.getValue<int64_t>();
                std::string col_name = schema.getField(c).getName();
                std::string table_name = schema.getField(c).getTableName();
                if (dm.isLoaded() && !table_name.empty() && dm.getColumnType(table_name, col_name) == DictColumnType::ENUM) {
                    std::string s = dm.lookupString(table_name, col_name, static_cast<int>(v));
                    if (s.empty()) {
                        std::cout << v << "\t";
                    } else {
                        std::cout << s << "(" << v << ")\t";
                    }
                } else {
                    const bool is_count = (col_name.find("count") != std::string::npos);
                    const bool is_agg =
                        is_count ||
                        (col_name.rfind("sum_", 0) == 0) ||
                        (col_name.rfind("avg_", 0) == 0);
                    if (is_agg) {
                        const int64_t mod = ReduceModPTotal(v);
                        std::ostringstream cell;
                        cell << "raw=" << v << "|mod=" << mod;
                        if (is_count) {
                            cell << "|scaled=" << mod;
                        } else {
                            cell << "|scaled=" << std::fixed << std::setprecision(6)
                                 << (static_cast<double>(mod) / 1000000.0);
                        }
                        std::cout << cell.str() << "\t";
                    } else {
                        std::cout << v << "\t";
                    }
                }
            } else if (ft == FieldType::FLOAT) {
                std::cout << f.getValue<float_t>() << "\t";
            } else if (ft == FieldType::STRING) {
                std::cout << f.getString() << "\t";
            } else {
                std::cout << "?\t";
            }
        }
        std::cout << std::endl;
    }
    if (print_rows < row_count) {
        std::cout << "... (" << (row_count - print_rows) << " more rows)" << std::endl;
    }
    std::cout << std::endl;
}

void convertEnumColumnsToIds(PlainColumnTable& table, const std::string& table_name,
                             const std::vector<std::string>& enum_columns) {
  auto& dm = DictionaryManager::getInstance();
  if (!dm.isLoaded()) {
    return;  // No dict loaded, skip
  }
  for (const std::string& col_name : enum_columns) {
    if (dm.getColumnType(table_name, col_name) != DictColumnType::ENUM) {
      continue;
    }
    auto column = table.getPlainColumn(col_name);
    if (!column) continue;
    for (const auto& chunk : column->getPlainChunks()) {
      if (!chunk) continue;
      auto& values = const_cast<std::vector<PlainField>&>(chunk->getValues());
      for (auto& field : values) {
        std::string str_val = field.getString();
        boost::algorithm::trim(str_val);  // TPC-H CHAR columns are space-padded
        int id = dm.registerOrLookup(table_name, col_name, str_val);
        field = PlainField(FieldType::LONG, static_cast<int64_t>(id));
      }
    }
  }
}

void convertDecimalColumnsToScaledInt(PlainColumnTable& table, const std::string& table_name,
                                      const std::vector<std::string>& decimal_columns) {
  auto& dm = DictionaryManager::getInstance();
  if (!dm.isLoaded()) {
    return;
  }
  for (const std::string& col_name : decimal_columns) {
    if (dm.getColumnType(table_name, col_name) != DictColumnType::DECIMAL) {
      continue;
    }
    int scale = dm.getScaleFactor(table_name, col_name);
    if (scale <= 0) scale = 1000000;
    auto column = table.getPlainColumn(col_name);
    if (!column) continue;
    for (const auto& chunk : column->getPlainChunks()) {
      if (!chunk) continue;
      auto& values = const_cast<std::vector<PlainField>&>(chunk->getValues());
      for (auto& field : values) {
        double d = 0.0;
        switch (field.getType()) {
          case FieldType::FLOAT:
            d = static_cast<double>(field.getValue<float_t>());
            break;
          case FieldType::INT:
            d = static_cast<double>(field.getValue<int32_t>());
            break;
          case FieldType::LONG:
          case FieldType::DATE:
            d = static_cast<double>(field.getValue<int64_t>());
            break;
          default:
            continue;  // Skip non-numeric; leave field unchanged
        }
        int64_t scaled = static_cast<int64_t>(d * scale + 0.5);
        field = PlainField(FieldType::LONG, scaled);
      }
    }
  }
}

}  // namespace vaultdb
