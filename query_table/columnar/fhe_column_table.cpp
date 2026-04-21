#include "fhe_column_table.h"

#include "fhe_column_type.h"
#include <query_table/query_table.h>
#include <query_table/query_schema.h>
#include <util/crypto_manager/fhe_manager.h>
#include <util/system_configuration.h>
#include <query_table/field/field_factory.h>
#include <query_table/columnar/fhe_quantization.h>
#include <query_table/columnar/plain_column_chunk.h>

#include <algorithm>
#include <cmath>
#include <ctime>
#include <stdexcept>
#include <utility>

namespace vaultdb {
namespace {
    /// Scale factor for decimal-to-integer encoding (TPC-H DECIMAL(15,2) convention).
    constexpr int kDecimalScaleFactor = 1000000;
    PlainField makePlainFieldFromInt64(int64_t value, FieldType type) {
        switch (type) {
            case FieldType::INT:
                return PlainField(FieldType::INT, static_cast<int32_t>(value));
            case FieldType::LONG:
                return PlainField(FieldType::LONG, static_cast<int64_t>(value));
            case FieldType::BOOL:
                return PlainField(FieldType::BOOL, value != 0);
            case FieldType::DATE:
                return PlainField(FieldType::LONG, static_cast<int64_t>(value));
            default:
                throw std::runtime_error("Unsupported field type for BFV decode");
        }
    }

    int64_t baseRelativeEpochDays() {
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

    int64_t dateFieldToRelativeDays(const PlainField& field) {
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
                throw std::runtime_error("Unsupported date field representation");
        }
    }
}

FheColumnTable::FheColumnTable(PlainTable* plain_table, const std::string& name)
        : ColumnTableBase(plain_table ? plain_table->getSchema() : QuerySchema(),
                          plain_table ? plain_table->getTrueTupleCount() : 0) {
    (void) name;
    if (!plain_table) {
        throw std::invalid_argument("FheColumnTable: plain_table is null");
    }
    auto snapshot = std::make_shared<PlainColumnTable>(plain_table);
    initializeFromPlainColumns(std::move(snapshot), {});
}

FheColumnTable::FheColumnTable(PlainColumnTable* plain_col_table,
                               const std::string& name,
                               const std::unordered_set<std::string>& encrypted_columns)
        : ColumnTableBase(plain_col_table ? plain_col_table->getSchema() : QuerySchema(),
                          plain_col_table ? plain_col_table->getRowCount() : 0) {
    (void) name;
    if (!plain_col_table) {
        throw std::invalid_argument("FheColumnTable: plain_col_table is null");
    }
    auto snapshot = std::make_shared<PlainColumnTable>(*plain_col_table);
    initializeFromPlainColumns(std::move(snapshot), encrypted_columns);
}

FheColumnTable::FheColumnTable(std::shared_ptr<PlainColumnTable> plain_col_table,
                               const std::unordered_set<std::string>& encrypted_columns)
        : ColumnTableBase(plain_col_table ? plain_col_table->getSchema() : QuerySchema(),
                          plain_col_table ? plain_col_table->getRowCount() : 0) {
    initializeFromPlainColumns(std::move(plain_col_table), encrypted_columns);
}

FheColumnTable::FheColumnTable(const QuerySchema& schema, size_t row_count)
        : ColumnTableBase(schema, row_count) {
    }

    std::shared_ptr<ColumnBase<void>> FheColumnTable::getColumn(const std::string& col_name) const {
        auto it = columns_.find(col_name);
        if (it == columns_.end()) {
            throw std::out_of_range("Column not found: " + col_name + " in FheColumnTable.");
        }
        return it->second;
    }

    std::vector<std::string> FheColumnTable::getColumnNames() const {
        std::vector<std::string> names;
        names.reserve(columns_.size());
        for (const auto& [name, _] : columns_) {
            names.push_back(name);
        }
        return names;
    }

    std::size_t FheColumnTable::getRowCount() const {
        return ColumnTableBase::getRowCount();
    }

std::shared_ptr<FheColumn> FheColumnTable::getFheColumn(const std::string& name) {
    auto it = columns_.find(name);
    if (it != columns_.end()) {
        return std::dynamic_pointer_cast<FheColumn>(it->second);
    }
    return ensureEncrypted(name);
}

std::shared_ptr<FheColumn> FheColumnTable::getFheColumn(const std::string& name) const {
    return const_cast<FheColumnTable*>(this)->getFheColumn(name);
}

bool FheColumnTable::hasEncryptedColumn(const std::string& name) const {
    return columns_.find(name) != columns_.end();
}

std::shared_ptr<FheColumn> FheColumnTable::ensureEncrypted(const std::string& name) {
    auto it = columns_.find(name);
    if (it != columns_.end()) {
        return std::dynamic_pointer_cast<FheColumn>(it->second);
    }

    if (!plain_table_) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: plain snapshot unavailable for column " + name);
    }

    auto plain_col = plain_table_->getPlainColumn(name);
    if (!plain_col) {
        // Skip if column doesn't exist in plain table (e.g., dummy_tag, indicator columns)
        // Check if it's an indicator column or dummy_tag
        if (name == "dummy_tag") {
            return nullptr;
        }
        // For other missing columns, still throw error but with more context
        throw std::runtime_error("FheColumnTable::ensureEncrypted: plain column missing for '" + name + "' (may be an indicator column)");
    }

    // Check if field exists in schema before calling getField (which uses at() internally)
    if (!this->schema_.hasField(name)) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: field '" + name + "' not found in schema");
    }
    
    QueryFieldDesc field_desc;
    try {
        field_desc = this->schema_.getField(name);
    } catch (const std::out_of_range& e) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: schema.getField('" + name + "') failed: " + e.what());
    }
    auto fhe_column = processPlainColumnToFhe(plain_col, field_desc);
    addEncryptedColumn(fhe_column);
    return fhe_column;
}

std::shared_ptr<FheColumn> FheColumnTable::ensureEncrypted(const std::string& name) const {
    return const_cast<FheColumnTable*>(this)->ensureEncrypted(name);
}

std::shared_ptr<FheColumn> FheColumnTable::ensureEncrypted(const std::string& name, bool for_aggregation,
                                                           double max_val, uint64_t row_count) {
    auto it = columns_.find(name);
    if (it != columns_.end()) {
        return std::dynamic_pointer_cast<FheColumn>(it->second);
    }

    if (!plain_table_) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: plain snapshot unavailable for column " + name);
    }

    auto plain_col = plain_table_->getPlainColumn(name);
    if (!plain_col) {
        if (name == "dummy_tag") {
            return nullptr;
        }
        throw std::runtime_error("FheColumnTable::ensureEncrypted: plain column missing for '" + name + "'");
    }

    if (!this->schema_.hasField(name)) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: field '" + name + "' not found in schema");
    }

    QueryFieldDesc field_desc;
    try {
        field_desc = this->schema_.getField(name);
    } catch (const std::out_of_range& e) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: schema.getField('" + name + "') failed: " + e.what());
    }

    std::shared_ptr<FheColumn> fhe_column;
    if (for_aggregation) {
        FheManager& manager = FheManager::getInstance();
        size_t rns_count = manager.getEffectiveRnsCount(max_val, row_count);
        if (rns_count == 0 || rns_count > 4) {
            rns_count = 1;
        }
        if (rns_count <= 1) {
            fhe_column = processPlainColumnToFhe(plain_col, field_desc);
        } else {
            fhe_column = processPlainColumnToBfvRns(plain_col, field_desc, rns_count);
        }
    } else {
        fhe_column = processPlainColumnToFhe(plain_col, field_desc);
    }
    addEncryptedColumn(fhe_column);
    return fhe_column;
}

std::shared_ptr<FheColumn> FheColumnTable::ensureEncrypted(const std::string& name, size_t rns_level) {
    auto it = columns_.find(name);
    if (it != columns_.end()) {
        auto fhe_col = std::dynamic_pointer_cast<FheColumn>(it->second);
        if (fhe_col && fhe_col->getRnsLevel() == rns_level) {
            return fhe_col;
        }
        if (fhe_col && fhe_col->getRnsLevel() != rns_level) {
            // Indicator/dummy_tag: filter may output multi-channel; aggregate may request different level.
            // Accept existing column so aggregate uses it as-is (caller must use getRnsLevel() on returned column).
            bool is_dummy_tag_col = (name == "dummy_tag");
            if (is_dummy_tag_col) {
                return fhe_col;
            }
            throw std::runtime_error("FheColumnTable::ensureEncrypted: column '" + name +
                "' already encrypted with rns_level " + std::to_string(fhe_col->getRnsLevel()) +
                "; cannot ensure rns_level " + std::to_string(rns_level) + " (incompatible).");
        }
    }

    if (!plain_table_) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: plain snapshot unavailable for column " + name);
    }

    auto plain_col = plain_table_->getPlainColumn(name);
    if (!plain_col) {
        if (name == "dummy_tag") {
            return nullptr;
        }
        throw std::runtime_error("FheColumnTable::ensureEncrypted: plain column missing for '" + name + "'");
    }

    if (!this->schema_.hasField(name)) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: field '" + name + "' not found in schema");
    }

    QueryFieldDesc field_desc;
    try {
        field_desc = this->schema_.getField(name);
    } catch (const std::out_of_range& e) {
        throw std::runtime_error("FheColumnTable::ensureEncrypted: schema.getField('" + name + "') failed: " + e.what());
    }

    std::shared_ptr<FheColumn> fhe_column;
    if (rns_level <= 1) {
        fhe_column = processPlainColumnToFhe(plain_col, field_desc);
    } else {
        fhe_column = processPlainColumnToBfvRns(plain_col, field_desc, rns_level);
    }
    addEncryptedColumn(fhe_column);
    return fhe_column;
}

void FheColumnTable::addColumn(const std::shared_ptr<FheColumn>& column) {
    addEncryptedColumn(column);
}

void FheColumnTable::setDummyTagColumn(const std::shared_ptr<FheColumn>& dummy_tag_col) {
    dummy_tag_column_ = dummy_tag_col;
}

PlainColumnTable* FheColumnTable::toPlainTable() const {
    if (!plain_table_) {
        throw std::runtime_error("FheColumnTable::toPlainTable: no plain snapshot available");
    }

    auto result = std::make_unique<PlainColumnTable>(this->schema_, this->row_count_);
    result->setFieldCount(this->getFieldCount());
    result->setHasDummy(this->getHasDummy());

    FheManager& manager = FheManager::getInstance();
    auto cc = manager.getIntegerCryptoContext();
    auto sk = manager.getIntegerSecretKey();
    if (!cc || !sk) {
        throw std::runtime_error("FheColumnTable::toPlainTable: BFV context or secret key unavailable");
    }

    const uint64_t modulus = cc->GetCryptoParameters()->GetPlaintextModulus();
    const int64_t half_modulus = static_cast<int64_t>(modulus / 2);

    for (int idx = 0; idx < this->schema_.getFieldCount(); ++idx) {
        const QueryFieldDesc& field_desc = this->schema_.getField(idx);
        const std::string& name = field_desc.getName();

        auto encrypted_it = columns_.find(name);
        if (encrypted_it != columns_.end()) {
            auto fhe_column = std::dynamic_pointer_cast<FheColumn>(encrypted_it->second);
            if (!fhe_column) {
                continue;
            }

            auto plain_column = std::make_shared<PlainColumn>(name);

            for (const auto& chunk : fhe_column->getFheChunks()) {
                lbcrypto::Plaintext pt;
                cc->Decrypt(sk, chunk->getCiphertext(), &pt);
                pt->SetLength(chunk->packed_count);

                auto packed = pt->GetPackedValue();
                std::vector<PlainField> decoded;
                decoded.reserve(packed.size());

                for (int64_t raw_value : packed) {
                    int64_t centered = raw_value;
                    if (centered > half_modulus) {
                        centered -= static_cast<int64_t>(modulus);
                    }
                    decoded.push_back(makePlainFieldFromInt64(centered, field_desc.getType()));
                }

                auto chunk_plain = std::make_shared<PlainColumnChunk>(decoded);
                plain_column->addChunk(chunk_plain);
            }

            result->addColumn(name, plain_column);
        } else {
            auto plain_column = plain_table_->getPlainColumn(name);
            if (!plain_column) {
                throw std::runtime_error("FheColumnTable::toPlainTable: missing plain column '" + name + "'");
            }
            result->addColumn(name, std::make_shared<PlainColumn>(*plain_column));
        }
    }

    return new PlainColumnTable(*result);
}

PlainColumnTable* FheColumnTable::reveal() const {
    return toPlainTable();
}

void FheColumnTable::initializeFromPlainColumns(
        std::shared_ptr<PlainColumnTable> plain_col_table,
        const std::unordered_set<std::string>& encrypted_columns) {
    if (!plain_col_table) {
        throw std::invalid_argument("FheColumnTable: plain_col_table is null");
    }

    plain_table_ = std::move(plain_col_table);

    this->schema_ = plain_table_->getSchema();
    this->row_count_ = plain_table_->getRowCount();
    this->setFieldCount(plain_table_->getFieldCount());
    this->setHasDummy(plain_table_->getHasDummy());
    columns_.clear();
    dummy_tag_column_.reset();

    if (!encrypted_columns.empty()) {
        encryptColumns(encrypted_columns);
    }
}

void FheColumnTable::addEncryptedColumn(const std::shared_ptr<FheColumn>& column) {
    if (!column) {
        throw std::invalid_argument("FheColumnTable::addEncryptedColumn: null column");
    }
    const std::string& name = column->getName();
    if (columns_.count(name)) {
        throw std::runtime_error("FheColumnTable::addEncryptedColumn: duplicate column '" + name + "'");
    }

    columns_[name] = column;
    if (name == "dummy_tag") {
        dummy_tag_column_ = column;
    }
}

std::shared_ptr<FheColumn> FheColumnTable::processPlainColumnToBfv(
        const std::shared_ptr<PlainColumn>& plain_column,
        const QueryFieldDesc& field_desc) {
    if (!plain_column) {
        throw std::invalid_argument("processPlainColumnToBfv: null plain column");
    }

    FheManager& manager = FheManager::getInstance();
    auto cc = manager.getIntegerCryptoContext();
    auto pk = manager.getIntegerPublicKey();
    if (!cc || !pk) {
        throw std::runtime_error("BFV CryptoContext or PublicKey not available");
    }

    const uint64_t plaintext_modulus = manager.getBFVPlaintextModulus();
    const size_t batch_size = manager.getBFVBatchSize();

    QuantizationParams params;
    params.simdSlots = static_cast<unsigned int>(batch_size);

    FheDataType data_type;
    switch (field_desc.getType()) {
        case FieldType::BOOL:
            data_type = FheDataType::BOOLEAN;
            break;
        case FieldType::DATE:
        case FieldType::INT:
        case FieldType::LONG:
        case FieldType::FLOAT:
            data_type = FheDataType::LONG;
            break;
        default:
            throw std::runtime_error("Unsupported field type for BFV column conversion");
    }
    FheTypeDescriptor type_desc(data_type, FheEncodingType::BFV_PACKED_ENCODING);

    auto fhe_column = std::make_shared<FheColumn>(field_desc.getName());
    std::vector<int64_t> batch;
    batch.reserve(batch_size);

            for (const auto& chunk_ptr : plain_column->getPlainChunks()) {
        const auto& values = chunk_ptr->getValues();
        for (const PlainField& field : values) {
            int64_t val = 0;
                    switch (field_desc.getType()) {
                case FieldType::INT:
                    val = static_cast<int64_t>(field.getValue<int32_t>());
                    break;
                case FieldType::LONG:
                    val = field.getValue<int64_t>();
                    break;
                case FieldType::BOOL:
                    val = field.getValue<bool>() ? 1 : 0;
                    break;
                case FieldType::DATE:
                    val = dateFieldToRelativeDays(field);
                    break;
                case FieldType::FLOAT:
                    // Scale by 1e6 to encode as integer (6 decimal places)
                    val = static_cast<int64_t>(std::round(static_cast<double>(field.getValue<float_t>()) * kDecimalScaleFactor));
                    break;
                default:
                    throw std::runtime_error("BFV encoding supports only INT, LONG, BOOL, DATE, FLOAT");
            }

            if (std::llabs(val) >= static_cast<int64_t>(plaintext_modulus / 2)) {
                throw std::runtime_error("Value out of BFV plaintext modulus range for column '" + field_desc.getName() + "'");
            }

            int64_t encoded = val % static_cast<int64_t>(plaintext_modulus);
            if (encoded < 0) {
                encoded += static_cast<int64_t>(plaintext_modulus);
            }

            batch.push_back(encoded);

            if (batch.size() == batch_size) {
                lbcrypto::Plaintext plaintext = cc->MakePackedPlaintext(batch);
                auto ciphertext = cc->Encrypt(pk, plaintext);
                fhe_column->addFheChunk(std::make_shared<FheColumnChunk>(
                        ciphertext, params, type_desc, batch.size()));
                batch.clear();
            }
        }
    }

    if (!batch.empty()) {
        lbcrypto::Plaintext plaintext = cc->MakePackedPlaintext(batch);
        auto ciphertext = cc->Encrypt(pk, plaintext);
        fhe_column->addFheChunk(std::make_shared<FheColumnChunk>(
                ciphertext, params, type_desc, batch.size()));
        }

        return fhe_column;
    }

std::shared_ptr<FheColumn> FheColumnTable::processPlainColumnToBfvRns(
        const std::shared_ptr<PlainColumn>& plain_column,
        const QueryFieldDesc& field_desc,
        size_t rns_count) {
    if (!plain_column) {
        throw std::invalid_argument("processPlainColumnToBfvRns: null plain column");
    }
    if (rns_count == 0 || rns_count > 4) {
        throw std::invalid_argument("processPlainColumnToBfvRns: rns_count must be 1..4");
    }

    FheManager& manager = FheManager::getInstance();
    const size_t batch_size = manager.getBFVBatchSize();
    const auto& moduli = manager.rns_moduli_;

    QuantizationParams params;
    params.simdSlots = static_cast<unsigned int>(batch_size);

    FheDataType data_type;
    switch (field_desc.getType()) {
        case FieldType::BOOL:
            data_type = FheDataType::BOOLEAN;
            break;
        case FieldType::DATE:
        case FieldType::INT:
        case FieldType::LONG:
        case FieldType::FLOAT:
            data_type = FheDataType::LONG;
            break;
        default:
            throw std::runtime_error("Unsupported field type for BFV RNS column conversion");
    }
    FheTypeDescriptor type_desc(data_type, FheEncodingType::BFV_PACKED_ENCODING);

    auto fhe_column = std::make_shared<FheColumn>(field_desc.getName());
    std::vector<std::vector<int64_t>> batches(rns_count);
    for (size_t i = 0; i < rns_count; ++i) {
        batches[i].reserve(batch_size);
    }

    for (const auto& chunk_ptr : plain_column->getPlainChunks()) {
        const auto& values = chunk_ptr->getValues();
        for (const PlainField& field : values) {
            int64_t val = 0;
            switch (field_desc.getType()) {
                case FieldType::INT:
                    val = static_cast<int64_t>(field.getValue<int32_t>());
                    break;
                case FieldType::LONG:
                    val = field.getValue<int64_t>();
                    break;
                case FieldType::BOOL:
                    val = field.getValue<bool>() ? 1 : 0;
                    break;
                case FieldType::DATE:
                    val = dateFieldToRelativeDays(field);
                    break;
                case FieldType::FLOAT:
                    // Scale by 1e6 to encode as integer (6 decimal places)
                    val = static_cast<int64_t>(std::round(static_cast<double>(field.getValue<float_t>()) * kDecimalScaleFactor));
                    break;
                default:
                    throw std::runtime_error("BFV RNS encoding supports only INT, LONG, BOOL, DATE, FLOAT");
            }

            for (size_t i = 0; i < rns_count; ++i) {
                int64_t mod = static_cast<int64_t>(moduli[i]);
                int64_t encoded = val % mod;
                if (encoded < 0) {
                    encoded += mod;
                }
                batches[i].push_back(encoded);
            }

            if (batches[0].size() == batch_size) {
                std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ciphers;
                ciphers.reserve(rns_count);
                for (size_t i = 0; i < rns_count; ++i) {
                    auto cc = manager.getRnsContext(i);
                    auto pk = manager.getRnsKeyPair(i).publicKey;
                    lbcrypto::Plaintext pt = cc->MakePackedPlaintext(batches[i]);
                    ciphers.push_back(cc->Encrypt(pk, pt));
                    batches[i].clear();
                }
                fhe_column->addFheChunk(std::make_shared<FheColumnChunk>(
                        ciphers, params, type_desc, batch_size));
            }
        }
    }

    if (!batches[0].empty()) {
        size_t count = batches[0].size();
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ciphers;
        ciphers.reserve(rns_count);
        for (size_t i = 0; i < rns_count; ++i) {
            auto cc = manager.getRnsContext(i);
            auto pk = manager.getRnsKeyPair(i).publicKey;
            lbcrypto::Plaintext pt = cc->MakePackedPlaintext(batches[i]);
            ciphers.push_back(cc->Encrypt(pk, pt));
        }
        fhe_column->addFheChunk(std::make_shared<FheColumnChunk>(
                ciphers, params, type_desc, count));
    }

    return fhe_column;
}

std::shared_ptr<FheColumnChunk> FheColumnTable::encryptSingleChunk(
        const std::string& col_name,
        size_t chunk_idx,
        size_t rns_count) const {
    if (!plain_table_) {
        throw std::runtime_error("FheColumnTable::encryptSingleChunk: plain snapshot unavailable");
    }
    auto plain_col = plain_table_->getPlainColumn(col_name);
    if (!plain_col) {
        throw std::runtime_error("FheColumnTable::encryptSingleChunk: plain column missing for '" + col_name + "'");
    }
    auto plain_chunks = plain_col->getPlainChunks();
    if (chunk_idx >= plain_chunks.size()) {
        throw std::out_of_range("FheColumnTable::encryptSingleChunk: chunk_idx " +
            std::to_string(chunk_idx) + " >= " + std::to_string(plain_chunks.size()));
    }

    if (!this->schema_.hasField(col_name)) {
        throw std::runtime_error("FheColumnTable::encryptSingleChunk: field '" + col_name + "' not in schema");
    }
    QueryFieldDesc field_desc = this->schema_.getField(col_name);

    FheManager& manager = FheManager::getInstance();
    const size_t batch_size = manager.getBFVBatchSize();

    FheDataType data_type;
    switch (field_desc.getType()) {
        case FieldType::BOOL:  data_type = FheDataType::BOOLEAN; break;
        case FieldType::DATE:
        case FieldType::INT:
        case FieldType::LONG:
        case FieldType::FLOAT: data_type = FheDataType::LONG; break;
        default:
            throw std::runtime_error("encryptSingleChunk: unsupported field type");
    }
    FheTypeDescriptor type_desc(data_type, FheEncodingType::BFV_PACKED_ENCODING);
    QuantizationParams params;
    params.simdSlots = static_cast<unsigned int>(batch_size);

    const auto& values = plain_chunks[chunk_idx]->getValues();

    auto encodeValue = [&](const PlainField& field) -> int64_t {
        switch (field_desc.getType()) {
            case FieldType::INT:   return static_cast<int64_t>(field.getValue<int32_t>());
            case FieldType::LONG:  return field.getValue<int64_t>();
            case FieldType::BOOL:  return field.getValue<bool>() ? 1 : 0;
            case FieldType::DATE:  return dateFieldToRelativeDays(field);
            case FieldType::FLOAT:
                return static_cast<int64_t>(std::round(
                    static_cast<double>(field.getValue<float_t>()) * kDecimalScaleFactor));
            default:
                throw std::runtime_error("encryptSingleChunk: unsupported type");
        }
    };

    if (rns_count <= 1) {
        // Single BFV context
        auto cc = manager.getIntegerCryptoContext();
        auto pk = manager.getIntegerPublicKey();
        const uint64_t plaintext_modulus = manager.getBFVPlaintextModulus();

        std::vector<int64_t> batch;
        batch.reserve(values.size());
        for (const PlainField& field : values) {
            int64_t val = encodeValue(field);
            int64_t encoded = val % static_cast<int64_t>(plaintext_modulus);
            if (encoded < 0) encoded += static_cast<int64_t>(plaintext_modulus);
            batch.push_back(encoded);
        }
        lbcrypto::Plaintext pt = cc->MakePackedPlaintext(batch);
        auto ct = cc->Encrypt(pk, pt);
        return std::make_shared<FheColumnChunk>(ct, params, type_desc, batch.size());
    } else {
        // Multi-channel RNS
        const auto& moduli = manager.rns_moduli_;
        size_t actual_rns = std::min(rns_count, moduli.size());

        std::vector<std::vector<int64_t>> batches(actual_rns);
        for (size_t i = 0; i < actual_rns; ++i) batches[i].reserve(values.size());

        for (const PlainField& field : values) {
            int64_t val = encodeValue(field);
            for (size_t i = 0; i < actual_rns; ++i) {
                int64_t mod = static_cast<int64_t>(moduli[i]);
                int64_t encoded = val % mod;
                if (encoded < 0) encoded += mod;
                batches[i].push_back(encoded);
            }
        }

        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ciphers;
        ciphers.reserve(actual_rns);
        for (size_t i = 0; i < actual_rns; ++i) {
            auto cc = manager.getRnsContext(i);
            auto pk = manager.getRnsKeyPair(i).publicKey;
            lbcrypto::Plaintext pt = cc->MakePackedPlaintext(batches[i]);
            ciphers.push_back(cc->Encrypt(pk, pt));
        }
        return std::make_shared<FheColumnChunk>(ciphers, params, type_desc, values.size());
    }
}

std::shared_ptr<FheColumn> FheColumnTable::processPlainColumnToFhe(
        const std::shared_ptr<PlainColumn>& plain_column,
        const QueryFieldDesc& field_desc) {
    switch (field_desc.getType()) {
        case FieldType::INT:
        case FieldType::LONG:
        case FieldType::BOOL:
        case FieldType::DATE:
        case FieldType::FLOAT:
            return processPlainColumnToBfv(plain_column, field_desc);
        default:
            throw std::runtime_error("processPlainColumnToFhe: unsupported field type for BFV pipeline");
    }
}

void FheColumnTable::encryptColumns(const std::unordered_set<std::string>& columns) {
    if (!plain_table_) {
        throw std::runtime_error("FheColumnTable::encryptColumns: plain table unavailable");
    }

    if (columns.empty()) {
        for (const auto& name : plain_table_->getColumnNames()) {
            // Skip if column is already encrypted
            if (hasEncryptedColumn(name)) {
                continue;
            }
            // Skip if column doesn't exist in plain table (e.g., dummy_tag)
            auto plain_col = plain_table_->getPlainColumn(name);
            if (!plain_col) {
                continue;  // Skip if column doesn't exist in plain table
            }
            auto encrypted = ensureEncrypted(name);
            if (!encrypted) {
                continue;  // Skip if encryption failed (e.g., indicator column)
            }
        }
        return;
    }

    for (const auto& name : columns) {
        if (hasEncryptedColumn(name)) {
            continue;
        }
        ensureEncrypted(name);
    }
}

} // namespace vaultdb
