#include "util/fhe/column_to_row_encoder.h"

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

#include "query_table/column_table.h"
#include "query_table/columnar/column_base.h"
#include "query_table/field/field_type.h"

namespace vaultdb {
namespace {

/// Same scale as FHE pipeline: l_extendedprice etc. encoded as round(float * kDecimalScaleFactor).
constexpr int kDecimalScaleFactor = 100;

PlainField makePlainFieldFromInt64(int64_t value, FieldType type) {
    switch (type) {
        case FieldType::INT:
            return PlainField(FieldType::INT, static_cast<int32_t>(value));
        case FieldType::LONG:
        case FieldType::DATE:
            return PlainField(FieldType::LONG, static_cast<int64_t>(value));
        case FieldType::BOOL:
            return PlainField(FieldType::BOOL, value != 0);
        case FieldType::FLOAT:
            return PlainField(FieldType::FLOAT, static_cast<float_t>(value) / static_cast<float_t>(kDecimalScaleFactor));
        case FieldType::INVALID:
        case FieldType::UNKNOWN:
            return PlainField(FieldType::LONG, static_cast<int64_t>(value));
        default:
            throw std::runtime_error("ColumnToRowEncode: unsupported field type for decrypt output");
    }
}

void setPlainColumnValues(
    PlainTable* output,
    const PlainColumn& plain_column,
    const int col_idx,
    const size_t row_count) {
    size_t row_cursor = 0;
    for (const auto& chunk : plain_column.getPlainChunks()) {
        const auto& values = chunk->getValues();
        for (const auto& value : values) {
            if (row_cursor >= row_count) {
                throw std::runtime_error("ColumnToRowEncode: plain column has more rows than table");
            }
            output->setField(static_cast<int>(row_cursor), col_idx, value);
            ++row_cursor;
        }
    }

    if (row_cursor != row_count) {
        throw std::runtime_error("ColumnToRowEncode: plain column row count mismatch");
    }
}

void setEncryptedColumnValues(
    PlainTable* output,
    const FheColumn& enc_column,
    const QueryFieldDesc& field_desc,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk,
    const size_t row_count) {
    if (!cc || !sk) {
        throw std::runtime_error("ColumnToRowEncode: crypto context or secret key is null");
    }

    const uint64_t modulus = cc->GetCryptoParameters()->GetPlaintextModulus();
    const int64_t half_modulus = static_cast<int64_t>(modulus / 2);

    size_t row_cursor = 0;
    for (const auto& chunk : enc_column.getFheChunks()) {
        if (!chunk || !chunk->getCiphertext()) {
            continue;
        }
        lbcrypto::Plaintext pt;
        cc->Decrypt(sk, chunk->getCiphertext(), &pt);
        const auto& packed = pt->GetPackedValue();
        const size_t take = std::min(packed.size(), static_cast<size_t>(chunk->packed_count));
        for (size_t i = 0; i < take; ++i) {
            if (row_cursor >= row_count) {
                throw std::runtime_error("ColumnToRowEncode: encrypted column has more rows than table");
            }
            int64_t raw = static_cast<int64_t>(packed[i]);
            if (raw > half_modulus) {
                raw -= static_cast<int64_t>(modulus);
            }
            auto field = makePlainFieldFromInt64(raw, field_desc.getType());
            output->setField(static_cast<int>(row_cursor), field_desc.getOrdinal(), field);
            ++row_cursor;
        }
    }

    if (row_cursor != row_count) {
        throw std::runtime_error("ColumnToRowEncode: encrypted column row count mismatch");
    }
}

}  // namespace

PlainTable* ColumnToRowEncode(
    const std::shared_ptr<FheColumnTable>& col_table,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk) {
    if (!col_table) {
        throw std::runtime_error("ColumnToRowEncode: input table is null");
    }

    const QuerySchema& schema = col_table->getSchema();
    const size_t row_count = col_table->getRowCount();
    auto output = new ColumnTable<bool>(row_count, schema);
    for (size_t row = 0; row < row_count; ++row) {
        output->setDummyTag(static_cast<int>(row), false);
    }

    auto plain_snapshot = col_table->getPlainSnapshot();

    if (schema.hasField("dummy_tag")) {
        auto plain_dummy = plain_snapshot ? plain_snapshot->getPlainColumn("dummy_tag") : nullptr;
        if (plain_dummy) {
            size_t row_cursor = 0;
            for (const auto& chunk : plain_dummy->getPlainChunks()) {
                const auto& values = chunk->getValues();
                for (const auto& value : values) {
                    if (row_cursor >= row_count) break;
                    // FHE convention: 1=valid, 0=dummy -> setDummyTag true when value is false
                    bool d = !value.getValue<bool>();
                    output->setDummyTag(static_cast<int>(row_cursor), d);
                    ++row_cursor;
                }
            }
        } else if (col_table->hasEncryptedColumn("dummy_tag")) {
            auto enc_dummy = col_table->getFheColumn("dummy_tag");
            if (enc_dummy && cc && sk) {
                size_t row_cursor = 0;
                for (const auto& chunk : enc_dummy->getFheChunks()) {
                    if (!chunk || !chunk->getCiphertext()) continue;
                    lbcrypto::Plaintext pt;
                    cc->Decrypt(sk, chunk->getCiphertext(), &pt);
                    const auto& packed = pt->GetPackedValue();
                    const size_t take = std::min(packed.size(), static_cast<size_t>(chunk->packed_count));
                    for (size_t i = 0; i < take; ++i) {
                        if (row_cursor >= row_count) break;
                        int64_t raw = static_cast<int64_t>(packed[i]);
                        // FHE convention: 1=valid, 0=dummy -> setDummyTag(row, true) when raw==0
                        bool d = (raw == 0);
                        output->setDummyTag(static_cast<int>(row_cursor), d);
                        ++row_cursor;
                    }
                }
            }
        }
    }

    for (int col_idx = 0; col_idx < schema.getFieldCount(); ++col_idx) {
        const auto& field_desc = schema.getField(col_idx);
        const auto& name = field_desc.getName();

        if (col_table->hasEncryptedColumn(name)) {
            auto enc_col = col_table->getFheColumn(name);
            if (!enc_col) {
                throw std::runtime_error("ColumnToRowEncode: encrypted column missing: " + name);
            }
            setEncryptedColumnValues(output, *enc_col, field_desc, cc, sk, row_count);
        } else {
            if (!plain_snapshot) {
                throw std::runtime_error("ColumnToRowEncode: plain snapshot missing for column: " + name);
            }
            auto plain_col = plain_snapshot->getPlainColumn(name);
            if (!plain_col) {
                throw std::runtime_error("ColumnToRowEncode: plain column missing: " + name);
            }
            setPlainColumnValues(output, *plain_col, col_idx, row_count);
        }
    }

    return output;
}

SecureTable* ColumnToSecureTableEncode(
    const std::shared_ptr<FheColumnTable>& col_table,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk) {
    std::unique_ptr<PlainTable> plain_table(ColumnToRowEncode(col_table, cc, sk));
    return plain_table->secretShare();
}

PlainTable* SecretShareToPlainTable(
    const QuerySchema& schema,
    const std::shared_ptr<PlainColumnTable>& plain_snapshot,
    const std::vector<int64_t>& aggregate_values) {
    if (!plain_snapshot) {
        throw std::runtime_error("SecretShareToPlainTable: plain_snapshot is null");
    }

    const size_t row_count = aggregate_values.size();
    if (row_count == 0) {
        throw std::runtime_error("SecretShareToPlainTable: aggregate_values is empty");
    }

    auto output = new ColumnTable<bool>(row_count, schema);

    for (size_t row = 0; row < row_count; ++row) {
        output->setDummyTag(static_cast<int>(row), false);
    }

    int group_by_col_count = 0;
    for (int col_idx = 0; col_idx < schema.getFieldCount(); ++col_idx) {
        const auto& field_desc = schema.getField(col_idx);
        const auto& name = field_desc.getName();

        auto plain_col = plain_snapshot->getPlainColumn(name);
        if (plain_col) {
            setPlainColumnValues(output, *plain_col, col_idx, row_count);
            ++group_by_col_count;
        }
    }

    int agg_col_idx = schema.getFieldCount() - 1;
    const auto& agg_field_desc = schema.getField(agg_col_idx);

    for (size_t row = 0; row < row_count; ++row) {
        int64_t value = aggregate_values[row];
        auto field = makePlainFieldFromInt64(value, agg_field_desc.getType());
        output->setField(static_cast<int>(row), agg_col_idx, field);
    }

    return output;
}

PlainTable* SecretShareToPlainTable(
    const QuerySchema& schema,
    const std::shared_ptr<PlainColumnTable>& plain_snapshot,
    const std::vector<std::vector<int64_t>>& aggregate_values_per_column,
    const std::vector<int>& agg_col_indices) {
    if (!plain_snapshot) {
        throw std::runtime_error("SecretShareToPlainTable: plain_snapshot is null");
    }
    if (aggregate_values_per_column.size() != agg_col_indices.size()) {
        throw std::runtime_error("SecretShareToPlainTable: aggregate_values_per_column size != agg_col_indices size");
    }
    size_t row_count = 0;
    if (aggregate_values_per_column.empty()) {
        // Sort-only plan: no aggregate columns; row count comes from plain snapshot.
        row_count = plain_snapshot->getRowCount();
    } else {
        for (const auto& col_vals : aggregate_values_per_column) {
            if (row_count == 0) {
                row_count = col_vals.size();
            } else if (col_vals.size() != row_count) {
                throw std::runtime_error("SecretShareToPlainTable: column value counts differ");
            }
        }
        if (row_count == 0) {
            throw std::runtime_error("SecretShareToPlainTable: aggregate_values_per_column is empty");
        }
    }

    auto output = new ColumnTable<bool>(row_count, schema);
    for (size_t row = 0; row < row_count; ++row) {
        output->setDummyTag(static_cast<int>(row), false);
    }

    for (int col_idx = 0; col_idx < schema.getFieldCount(); ++col_idx) {
        const auto& field_desc = schema.getField(col_idx);
        const auto& name = field_desc.getName();
        auto plain_col = plain_snapshot->getPlainColumn(name);
        if (plain_col) {
            setPlainColumnValues(output, *plain_col, col_idx, row_count);
        }
    }

    // Step 5 MPC input: B uses R (Val_B), C uses (M-R) (Val_C). Values kept as signed int64_t
    // so Secure_Sum = Share(Val_C) + Share(Val_B) reveals M; 64-bit overflow is well-defined.
    for (size_t i = 0; i < agg_col_indices.size(); ++i) {
        int agg_col_idx = agg_col_indices[i];
        const auto& agg_field_desc = schema.getField(agg_col_idx);
        const auto& values = aggregate_values_per_column[i];
        for (size_t row = 0; row < values.size(); ++row) {
            auto field = makePlainFieldFromInt64(values[row], agg_field_desc.getType());
            output->setField(static_cast<int>(row), agg_col_idx, field);
        }
    }

    return output;
}

}  // namespace vaultdb
