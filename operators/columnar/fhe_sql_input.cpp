#include "fhe_sql_input.h"
#include <data/psql_data_provider.h>
#include <util/system_configuration.h>
#include <util/dictionary_manager.h>
#include <util/fhe/fhe_helpers.h>
#include <util/utilities.h>
#include <query_table/columnar/column_table_base.h>
#include <query_table/columnar/plain_column_chunk.h>
#include <query_table/columnar/column_base.h>
#include <query_table/columnar/fhe_column_table.h>
#include <util/crypto_manager/fhe_manager.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string.hpp>
#include <ctime>
#include <unordered_set>
#include <util/google_test_flags.h>
#include "openfhe.h"

namespace vaultdb {

namespace {
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

int64_t relativeDaysFromField(const PlainField& field) {
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

bool isDateLikeColumn(const std::string& name) {
    auto lowered = boost::algorithm::to_lower_copy(name);
    return lowered.find("date") != std::string::npos;
}

void convertDateColumns(PlainColumnTable& table) {
    const QuerySchema& schema = table.getSchema();
    for (int idx = 0; idx < schema.getFieldCount(); ++idx) {
        const auto& desc = schema.getField(idx);
        if (desc.getType() != FieldType::DATE && !isDateLikeColumn(desc.getName())) {
            continue;
        }

        auto column = table.getPlainColumn(desc.getName());
        if (!column) {
            continue;
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
}
}

// --- Constructor ---
    FheSqlInput::FheSqlInput(const std::string &db, const std::string &sql,
                             const SortDefinition &sort_def, size_t tuple_limit,
                             size_t output_cardinality,
                             bool bin_flag,
                             const std::vector<int32_t>& bin_group_by_ordinals)
            : ColumnOperator(sort_def, output_cardinality),
              original_input_query_(sql),
              input_query_(sql),
              db_name_(db),
              tuple_limit_(tuple_limit),
              bin_flag_(bin_flag),
              bin_group_by_ordinals_(bin_group_by_ordinals) {
    }

// --- Copy Constructor ---
    FheSqlInput::FheSqlInput(const FheSqlInput& src)
            : ColumnOperator(src),
              original_input_query_(src.original_input_query_),
              input_query_(src.input_query_),
              db_name_(src.db_name_),
              tuple_limit_(src.tuple_limit_),
              bin_flag_(src.bin_flag_),
              bin_group_by_ordinals_(src.bin_group_by_ordinals_) {
    }

    // --- Run Method ---
    std::shared_ptr<ColumnTableBase<void>> FheSqlInput::runSelf() {
        startTiming();
        runQuery();

        if (!plain_input_) {
            throw std::runtime_error("FheSqlInput: Failed to fetch plain column table for query: " + original_input_query_);
        }

        // Add dummy_tag column to plain_input_ if it doesn't exist
        if (!plain_input_->getPlainColumn("dummy_tag")) {
            // Add dummy_tag field to schema (ordinal -1 per common/defs.h)
            QuerySchema& schema = const_cast<QuerySchema&>(plain_input_->getSchema());
            const int kDummyTagOrdinal = -1;
            QueryFieldDesc dummy_field(kDummyTagOrdinal, "dummy_tag", "", FieldType::BOOL);
            schema.putField(dummy_field);
            schema.initializeFieldOffsets();
            
            // Create dummy_tag column with all TRUE (1=valid) per FHE convention
            size_t row_count = plain_input_->getRowCount();
            auto dummy_column = std::make_shared<PlainColumn>("dummy_tag");
            std::vector<PlainField> dummy_values(row_count, PlainField(FieldType::BOOL, true));
            auto dummy_chunk = std::make_shared<PlainColumnChunk>(dummy_values);
            dummy_column->addChunk(dummy_chunk);
            
            // Add column to table
            plain_input_->addColumn("dummy_tag", dummy_column);
        }

        // Always create bin metadata if group-by ordinals are provided (for aggregate support)
        if (!bin_group_by_ordinals_.empty()) {
            // Create a copy of plain_input_ for bin metadata creation
            std::shared_ptr<PlainColumnTable> plain_copy = std::make_shared<PlainColumnTable>(*plain_input_);
            // Create FheColumnTable with plaintext data (no encryption yet)
            // Pass empty encrypted_columns set to keep everything in plaintext
            auto output_table = std::make_shared<FheColumnTable>(plain_copy, std::unordered_set<std::string>{});
            // Create bin metadata with continuous packing (only metadata, no encryption)
            createBinMetadata(output_table, plain_copy);
            if (FLAGS_all_column_encrypt) {
                auto col_names = output_table->getPlainSnapshot()->getColumnNames();
                const auto& schema = output_table->getSchema();
                size_t encrypted_count = 0;
                for (const auto& col_name : col_names) {
                    if (schema.hasField(col_name)) {
                        auto ft = schema.getField(col_name).getType();
                        if (ft == FieldType::STRING) continue;  // skip non-numeric
                    }
                    output_table->ensureEncrypted(col_name, static_cast<size_t>(3));
                    ++encrypted_count;
                }
                std::cout << "[FheSqlInput] all_column_encrypt: " << encrypted_count << "/" << col_names.size() << " columns encrypted" << std::endl;
            }
            this->output_ = output_table;
        } else {
            // Normal path: create FheColumnTable but keep in plaintext (no encryption)
            std::shared_ptr<PlainColumnTable> plain_shared = std::move(plain_input_);
            std::shared_ptr<FheColumnTable> output_table = std::make_shared<FheColumnTable>(plain_shared, std::unordered_set<std::string>{});
            if (FLAGS_all_column_encrypt) {
                auto col_names = output_table->getPlainSnapshot()->getColumnNames();
                const auto& schema = output_table->getSchema();
                size_t encrypted_count = 0;
                for (const auto& col_name : col_names) {
                    if (schema.hasField(col_name)) {
                        auto ft = schema.getField(col_name).getType();
                        if (ft == FieldType::STRING) continue;  // skip non-numeric
                    }
                    output_table->ensureEncrypted(col_name, static_cast<size_t>(3));
                    ++encrypted_count;
                }
                std::cout << "[FheSqlInput] all_column_encrypt: " << encrypted_count << "/" << col_names.size() << " columns encrypted" << std::endl;
            }
            this->output_ = output_table;
        }
        
        endTiming();
        printTiming();
        return this->output_;
    }

    // --- Internal runQuery Method ---
    void FheSqlInput::runQuery() {
        std::string current_sql = input_query_;

        if (tuple_limit_ > 0) {
            std::string temp_sql = input_query_;
            if (!temp_sql.empty() && temp_sql.back() == ';') {
                temp_sql.pop_back();
            }
            boost::replace_all(temp_sql, ";", "");
            current_sql = "SELECT * FROM (" + temp_sql + ") AS input LIMIT " + std::to_string(tuple_limit_);
        }

        PsqlDataProvider provider;
        plain_input_ = provider.getQueryColumnTable(db_name_, current_sql);

        if (plain_input_) {
            convertDateColumns(*plain_input_);
            // Phase 5: Convert enum columns to dictionary IDs (dict must be loaded by Party B SetUp)
            auto& dm = DictionaryManager::getInstance();
            if (dm.isLoaded()) {
                convertEnumColumnsToIds(*plain_input_, "lineitem", {"l_returnflag", "l_linestatus", "l_shipmode"});
                convertEnumColumnsToIds(*plain_input_, "orders", {"o_orderstatus", "o_orderpriority"});
                convertEnumColumnsToIds(*plain_input_, "customer", {"c_mktsegment"});
                convertEnumColumnsToIds(*plain_input_, "part", {"p_brand", "p_container"});
                convertEnumColumnsToIds(*plain_input_, "nation", {"n_name"});
                convertEnumColumnsToIds(*plain_input_, "region", {"r_name"});
            }
        }

        if (plain_input_) {
            output_schema_ = plain_input_->getSchema();
            output_cardinality_ = plain_input_->getRowCount();
        } else {
            output_schema_ = QuerySchema();
            output_cardinality_ = 0;
        }
    }

    // --- Operator Info ---
    OperatorType FheSqlInput::getType() const {
        return OperatorType::FHE_SQL_INPUT;
    }

    std::string FheSqlInput::getParameters() const {
        return "|" + input_query_ + ", tuple_count=" + std::to_string(output_cardinality_);
    }

    FheSqlInput* FheSqlInput::clone() const {
        return new FheSqlInput(*this);
    }

    bool FheSqlInput::operator==(const ColumnOperator& rhs) const {
        if (rhs.getType() != OperatorType::FHE_SQL_INPUT) return false;

        const auto* other_node_ptr = dynamic_cast<const FheSqlInput*>(&rhs);
        if (!other_node_ptr) return false;

        const FheSqlInput& other_node = *other_node_ptr;

        return input_query_ == other_node.input_query_ &&
               db_name_ == other_node.db_name_ &&
               tuple_limit_ == other_node.tuple_limit_ &&
               original_input_query_ == other_node.original_input_query_ &&
               sort_definition_ == other_node.sort_definition_;
    }

// --- Sort Logic ---
    void FheSqlInput::updateCollation() {
        if (sort_definition_.empty()) {
            input_query_ = original_input_query_;
            return;
        }

        if (sort_definition_ == sort_definition_) {
            input_query_ = original_input_query_;
            return;
        }

        std::string sql_to_sort = original_input_query_;
        if (!sql_to_sort.empty() && sql_to_sort.back() == ';') {
            sql_to_sort.pop_back();
        }
        boost::replace_all(sql_to_sort, ";", "");

        std::string new_sql = "SELECT * FROM (" + sql_to_sort + ") AS to_sort ORDER BY ";
        for (size_t i = 0; i < sort_definition_.size(); ++i) {
            if (i > 0) new_sql += ", ";
            new_sql += "(" + std::to_string(sort_definition_[i].first + 1) + ") ";
            new_sql += (sort_definition_[i].second == SortDirection::DESCENDING) ? "DESC" : "ASC";
        }

        input_query_ = new_sql;

        runQuery();
    }

    // Helper: Compare group-by values for two rows
    bool rowsEqual(const std::shared_ptr<PlainColumnTable>& table,
                  const std::vector<int32_t>& group_by_ordinals,
                  size_t row1, size_t row2) {
        for (int32_t ord : group_by_ordinals) {
            auto field_desc = table->getSchema().getField(ord);
            auto column = table->getPlainColumn(field_desc.getName());
            if (!column) {
                throw std::runtime_error("FheSqlInput: group-by column not found: " + field_desc.getName());
            }

            size_t chunk_idx1 = 0, offset1 = row1;
            size_t chunk_idx2 = 0, offset2 = row2;
            for (const auto& chunk : column->getPlainChunks()) {
                if (!chunk) continue;
                if (offset1 < chunk->getValues().size()) break;
                offset1 -= chunk->getValues().size();
                chunk_idx1++;
            }
            for (const auto& chunk : column->getPlainChunks()) {
                if (!chunk) continue;
                if (offset2 < chunk->getValues().size()) break;
                offset2 -= chunk->getValues().size();
                chunk_idx2++;
            }

            const auto& chunks = column->getPlainChunks();
            if (chunk_idx1 >= chunks.size() || chunk_idx2 >= chunks.size() ||
                !chunks[chunk_idx1] || !chunks[chunk_idx2]) {
                return false;
            }

            const auto& val1 = chunks[chunk_idx1]->getValues()[offset1];
            const auto& val2 = chunks[chunk_idx2]->getValues()[offset2];

            if (val1 != val2) {
                return false;
            }
        }
        return true;
    }

    // Helper: Get field value from plain table
    PlainField getFieldValue(const std::shared_ptr<PlainColumnTable>& table,
                            int32_t ordinal, size_t row) {
        auto field_desc = table->getSchema().getField(ordinal);
        auto column = table->getPlainColumn(field_desc.getName());
        if (!column) {
            throw std::runtime_error("FheSqlInput: column not found: " + field_desc.getName());
        }

        size_t chunk_idx = 0, offset = row;
        for (const auto& chunk : column->getPlainChunks()) {
            if (!chunk) continue;
            if (offset < chunk->getValues().size()) break;
            offset -= chunk->getValues().size();
            chunk_idx++;
        }

        const auto& chunks = column->getPlainChunks();
        if (chunk_idx >= chunks.size() || !chunks[chunk_idx]) {
            throw std::runtime_error("FheSqlInput: row index out of range");
        }

        return chunks[chunk_idx]->getValues()[offset];
    }

    // Create bin metadata and encrypt columns according to group boundaries
    // This ensures data is packed efficiently with group boundaries respected
    void FheSqlInput::createBinMetadata(std::shared_ptr<FheColumnTable> output_table,
                                        std::shared_ptr<PlainColumnTable> plain_snapshot) {
        if (!plain_snapshot) {
            throw std::runtime_error("FheSqlInput::createBinMetadata: plain_snapshot is null");
        }
        size_t row_count = plain_snapshot->getRowCount();
        if (row_count == 0) {
            return;
        }

        // Find group boundaries (assuming input is sorted by group-by columns)
        std::vector<size_t> group_starts;
        group_starts.push_back(0);
        for (size_t i = 1; i < row_count; ++i) {
            if (!rowsEqual(plain_snapshot, bin_group_by_ordinals_, i - 1, i)) {
                group_starts.push_back(i);
            }
        }
        group_starts.push_back(row_count);  // End marker
        size_t num_groups = group_starts.size() - 1;

        FheManager& fhe_manager = FheManager::getInstance();
        const size_t batch_size = fhe_manager.getBFVBatchSize();

        // Process each column to compute bin metadata (without encryption)
        std::vector<BinGroupMetadata> bin_metadata;
        bin_metadata.reserve(num_groups);

        // Initialize bin metadata for each group
        for (size_t group_idx = 0; group_idx < num_groups; ++group_idx) {
            BinGroupMetadata group_meta;
            group_meta.original_start_row = group_starts[group_idx];
            group_meta.original_end_row = group_starts[group_idx + 1];
            
            // Store group key values
            for (int32_t ord : bin_group_by_ordinals_) {
                PlainField key_field = getFieldValue(plain_snapshot, ord, group_starts[group_idx]);
                group_meta.group_key_values.push_back(key_field);
            }
            
            bin_metadata.push_back(group_meta);
        }

        // Process each column to compute chunk index ranges (without encryption)
        for (const auto& col_name : plain_snapshot->getColumnNames()) {
            // Skip dummy_tag column - it's not in the plain snapshot
            if (col_name == "dummy_tag") continue;
            
            auto plain_column = plain_snapshot->getPlainColumn(col_name);
            if (!plain_column) continue;

            // Continuous packing: fill ciphertexts efficiently, allowing multiple groups per chunk
            size_t current_chunk_idx = 0;
            size_t current_slot_in_chunk = 0;

            // Process each group with continuous packing
            for (size_t group_idx = 0; group_idx < num_groups; ++group_idx) {
                size_t group_start = group_starts[group_idx];
                size_t group_end = group_starts[group_idx + 1];
                size_t group_size = group_end - group_start;

                size_t start_chunk_idx = current_chunk_idx;
                size_t start_slot_in_chunk = current_slot_in_chunk;
                
                // Fill current buffer continuously (multiple groups can share a ciphertext)
                size_t remaining_in_group = group_size;
                while (remaining_in_group > 0) {
                    size_t available_in_chunk = batch_size - current_slot_in_chunk;
                    size_t to_pack = std::min(remaining_in_group, available_in_chunk);
                    
                    // Record slot range for this group in this chunk
                    size_t range_start = current_slot_in_chunk;
                    size_t range_end = current_slot_in_chunk + to_pack - 1;
                    
                    // Store slot range in chunk_slot_ranges
                    bin_metadata[group_idx].column_bin_info[col_name].chunk_slot_ranges[current_chunk_idx] = {range_start, range_end};
                    
                    remaining_in_group -= to_pack;
                    current_slot_in_chunk += to_pack;
                    
                    // If chunk is full, move to next chunk
                    if (current_slot_in_chunk >= batch_size) {
                        current_chunk_idx++;
                        current_slot_in_chunk = 0;
                    }
                }
                
                size_t end_chunk_idx = current_chunk_idx;
                
                // Update bin metadata for this column
                ColumnBinInfo& bin_info = bin_metadata[group_idx].column_bin_info[col_name];
                bin_info.start_chunk_idx = start_chunk_idx;
                bin_info.end_chunk_idx = end_chunk_idx;
                bin_info.total_packed_count = group_size;
            }
        }

        // Now reorganize plain columns according to bin metadata structure (group-based packing)
        // Create new PlainColumnTable with data packed according to bin metadata chunks
        // This ensures each chunk contains exactly batch_size rows (with padding if needed)
        
        // Find the maximum chunk index needed across all columns
        size_t max_chunk_idx = 0;
        for (const auto& col_name : plain_snapshot->getColumnNames()) {
            if (col_name == "dummy_tag") continue;
            for (const auto& group_meta : bin_metadata) {
                auto it = group_meta.column_bin_info.find(col_name);
                if (it != group_meta.column_bin_info.end()) {
                    max_chunk_idx = std::max(max_chunk_idx, it->second.end_chunk_idx);
                }
            }
        }

        // Create new plain columns with bin metadata structure
        auto reorganized_plain_table = std::make_shared<PlainColumnTable>(plain_snapshot->getSchema(), row_count);
        
        for (const auto& col_name : plain_snapshot->getColumnNames()) {
            // Skip dummy_tag column (will be handled separately)
            if (col_name == "dummy_tag") continue;
            
            auto plain_column = plain_snapshot->getPlainColumn(col_name);
            if (!plain_column) continue;
            
            const QueryFieldDesc& field_desc = plain_snapshot->getSchema().getField(col_name);
            
            // Skip unsupported types (FHE encryption not supported, but keep in plain for now)
            // FLOAT (decimal) is supported: BFV path scales by 100 before encoding
            if (field_desc.getType() != FieldType::INT &&
                field_desc.getType() != FieldType::LONG &&
                field_desc.getType() != FieldType::BOOL &&
                field_desc.getType() != FieldType::DATE &&
                field_desc.getType() != FieldType::FLOAT &&
                field_desc.getType() != FieldType::STRING) {
                continue; // Skip unsupported types
            }

            // Create new plain column with bin metadata structure
            auto new_plain_column = std::make_shared<PlainColumn>(col_name);

            // Initialize plain field batches (one per chunk index)
            // Pre-allocate to batch_size and fill with default values for padding
            PlainField default_field;
            switch (field_desc.getType()) {
                case FieldType::INT:
                    default_field = PlainField(FieldType::INT, int32_t(0));
                    break;
                case FieldType::LONG:
                case FieldType::DATE:
                    default_field = PlainField(FieldType::LONG, int64_t(0));
                    break;
                case FieldType::BOOL:
                    default_field = PlainField(FieldType::BOOL, false);
                    break;
                case FieldType::FLOAT:
                    default_field = PlainField(FieldType::FLOAT, 0.0f);
                    break;
                case FieldType::STRING: {
                    // For STRING, pad to the required length (empty string padded to field length)
                    size_t str_len = field_desc.getStringLength();
                    std::string empty_str(str_len, ' ');
                    default_field = PlainField(FieldType::STRING, empty_str);
                    break;
                }
                default:
                    default_field = PlainField(FieldType::LONG, int64_t(0));
                    break;
            }
            
            std::vector<std::vector<PlainField>> plain_batches(max_chunk_idx + 1);
            for (size_t i = 0; i <= max_chunk_idx; ++i) {
                plain_batches[i].resize(batch_size, default_field);
            }
            
            // Pack data according to chunk_slot_ranges from bin metadata
            // For each group, fill the corresponding slot ranges in the appropriate chunks
            for (size_t group_idx = 0; group_idx < num_groups; ++group_idx) {
                const auto& group_meta = bin_metadata[group_idx];
                auto it = group_meta.column_bin_info.find(col_name);
                if (it == group_meta.column_bin_info.end()) continue;
                
                const auto& bin_info = it->second;
                size_t group_start = group_meta.original_start_row;
                size_t group_end = group_meta.original_end_row;
                
                // Pack this group's data according to chunk_slot_ranges
                size_t group_data_offset = 0; // Offset within current group's data
                for (const auto& [chunk_idx, slot_range] : bin_info.chunk_slot_ranges) {
                    size_t range_start = slot_range.first;
                    size_t range_end = slot_range.second;
                    size_t range_size = range_end - range_start + 1;
                    
                    // Fill the slot range with data from this group's rows
                    for (size_t local_idx = 0; local_idx < range_size; ++local_idx) {
                        size_t slot = range_start + local_idx;
                        if (slot >= batch_size) break;
                        
                        size_t row_idx = group_start + group_data_offset + local_idx;
                        if (row_idx >= group_end || row_idx >= row_count) break;
                        
                        // Get field value at this row
                        PlainField field = getFieldValue(plain_snapshot, field_desc.getOrdinal(), row_idx);
        
                        // Set field at the specified slot (batch is already sized to batch_size)
                        plain_batches[chunk_idx][slot] = field;
                    }
                    
                    group_data_offset += range_size;
                }
            }
            
            // Create plain chunks (already padded to batch_size)
            for (size_t chunk_idx = 0; chunk_idx <= max_chunk_idx; ++chunk_idx) {
                // Create plain chunk (batch is already padded to batch_size)
                auto plain_chunk = std::make_shared<PlainColumnChunk>(plain_batches[chunk_idx]);
                new_plain_column->addChunk(plain_chunk);
            }
            
            // Add reorganized column to new plain table
            reorganized_plain_table->addColumn(col_name, new_plain_column);
        }
        
        // =========================================================
        // [FIX] Handle dummy_tag separately
        // We need to create a packed dummy_tag column that matches the structure 
        // of other packed columns (Chunks of size batch_size).
        // FHE convention: 1=valid, 0=dummy; initial rows are all valid.
        // =========================================================
        {
            auto dummy_column = std::make_shared<PlainColumn>("dummy_tag");
            
            // Default value for dummy_tag is true (1=valid)
            PlainField dummy_val(FieldType::BOOL, true);

            // Create chunks aligned with max_chunk_idx
            for (size_t chunk_idx = 0; chunk_idx <= max_chunk_idx; ++chunk_idx) {
                // Create a chunk filled with 'false', size = batch_size
                std::vector<PlainField> dummy_chunk_vals(batch_size, dummy_val);
                auto dummy_chunk = std::make_shared<PlainColumnChunk>(dummy_chunk_vals);
                dummy_column->addChunk(dummy_chunk);
            }
            
            reorganized_plain_table->addColumn("dummy_tag", dummy_column);
        }
        // =========================================================
        
        // Set reorganized plain table in output_table
        output_table->setPlainTable(reorganized_plain_table);
        
        // Set bin metadata in output table
        output_table->setBinMetadata(bin_metadata, bin_group_by_ordinals_);
    }

} // namespace vaultdb
