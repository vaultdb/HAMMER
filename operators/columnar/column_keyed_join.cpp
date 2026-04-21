#include "column_keyed_join.h"
#include <query_table/columnar/column_table_base.h>
#include <query_table/columnar/column_base.h>
#include <query_table/columnar/plain_column_chunk.h>
#include <query_table/field/field.h>
#include <util/crypto_manager/fhe_manager.h>
#include <util/simd_plain_operations.h>
#include <cmath>
#include <algorithm>
#include <chrono>

using namespace vaultdb;

// Static member definition
bool ColumnKeyedJoin::debug_enabled_ = false;

// FHE operation tracking variables
static uint32_t eval_rotate_count_ = 0;
static uint32_t eval_mult_count_ = 0;
static uint32_t eval_bootstrap_count_ = 0;
static uint32_t current_mult_depth_ = 0;
static const uint32_t MAX_MULT_DEPTH_ = FheManager::getInstance().bfv_mult_depth_;

// Per-data-flow depth tracking
static std::map<std::string, uint32_t> data_flow_depths_;
static std::map<std::string, uint32_t> max_data_flow_depths_;

// FHE operation tracking functions
void ColumnKeyedJoin::resetFHEOperationCounts() {
    eval_rotate_count_ = 0;
    eval_mult_count_ = 0;
    eval_bootstrap_count_ = 0;
    current_mult_depth_ = 0;
    ColumnKeyedJoin::resetDataFlowDepths();
}

void ColumnKeyedJoin::trackEvalRotate() {
    eval_rotate_count_++;
}

void ColumnKeyedJoin::trackEvalMult() {
    eval_mult_count_++;
    current_mult_depth_++;
    
    // Check if we need bootstrapping
    if (current_mult_depth_ >= MAX_MULT_DEPTH_) {
        eval_bootstrap_count_++;
        current_mult_depth_ = 0; // Reset after bootstrapping
    }
}

void ColumnKeyedJoin::printFHEOperationCounts() {
    std::cout << "\n=== FHE Operation Counts ===" << std::endl;
    std::cout << "EvalRotate operations: " << eval_rotate_count_ << std::endl;
    std::cout << "EvalMult operations: " << eval_mult_count_ << std::endl;
    std::cout << "EvalBootstrap operations: " << eval_bootstrap_count_ << std::endl;
    std::cout << "Current multiplicative depth: " << current_mult_depth_ << std::endl;
    std::cout << "Max multiplicative depth before bootstrapping: " << MAX_MULT_DEPTH_ << std::endl;
    
    // Print per-data-flow analysis
    std::cout << "\n=== Per-Data-Flow Depth Analysis ===" << std::endl;
    for (const auto& [flow_name, max_depth] : max_data_flow_depths_) {
        std::cout << "Data flow '" << flow_name << "': max depth = " << max_depth;
        if (max_depth >= MAX_MULT_DEPTH_) {
            std::cout << " (REQUIRES BOOTSTRAPPING)";
        }
        std::cout << std::endl;
    }
    std::cout << "================================\n" << std::endl;
}

// Debug print helper function
void ColumnKeyedJoin::debugPrint(const std::string& message) {
    if (debug_enabled_) {
        std::cout << message << std::endl;
    }
}

// Note: SIMD operations are now handled by simd_plain_operations.h/cpp

ColumnKeyedJoin::ColumnKeyedJoin(std::shared_ptr<PlainColumnTable> lhs,
                                 std::shared_ptr<PlainColumnTable> rhs,
                                 const SIMDPlainGenericExpression& join_condition,
                                 const std::string& fk_join_key,
                                 const std::string& pk_join_key,
                                 int foreign_key_input)
        : ColumnOperator<bool>(SortDefinition{}, lhs->getRowCount()),  // required base init
          lhs_table_(std::move(lhs)),
          rhs_table_(std::move(rhs)),
          join_condition_(join_condition),
          fk_join_key_name_(fk_join_key),
          pk_join_key_name_(pk_join_key),
          foreign_key_input_(foreign_key_input) {

    if (foreign_key_input_ != 0 && foreign_key_input_ != 1) {
        throw std::invalid_argument("foreign_key_input must be 0 (lhs is FK) or 1 (rhs is FK)");
    }
}

std::shared_ptr<ColumnTableBase<bool>> ColumnKeyedJoin::runSelf() {
    debugPrint("[Column Keyed Join] Starting plaintext keyed join");

    // Reset FHE operation counters
    resetFHEOperationCounts();

    FheManager& fhe_manager = FheManager::getInstance();
    auto cc = fhe_manager.getRealCryptoContext();
    size_t chunk_size = fhe_manager.bfv_batch_size_;

    // Precompute rotated FK keys for caching
    precomputeRotatedFKKeys(chunk_size);

    // Perform the join
    auto result = performJoin(chunk_size);

    // Print FHE operation counts
    printFHEOperationCounts();

    this->output_ = result;
    return this->output_;
}

std::vector<std::vector<std::vector<PlainField>>> ColumnKeyedJoin::getPrecomputedCache(const size_t chunk_size) {
    // Precompute rotated FK keys for caching
    precomputeRotatedFKKeys(chunk_size);

    // Return the precomputed cache
    return fk_rotated_keys_cache_;
}

void ColumnKeyedJoin::precomputeRotatedFKKeys(const size_t chunk_size) {
    debugPrint("[Column Keyed Join] Starting precomputation of rotated FK keys");

    // Determine which table is the FK table
    auto fk_table = (foreign_key_input_ == 0) ? lhs_table_ : rhs_table_;
    auto fk_column = fk_table->getPlainColumn(fk_join_key_name_);

    if (!fk_column) {
        throw std::runtime_error("FK join key column not found: " + fk_join_key_name_);
    }

    const auto& fk_chunks = fk_column->getPlainChunks();
    size_t num_chunks = fk_chunks.size();

    debugPrint("[Column Keyed Join] Precomputing " + std::to_string(num_chunks) + " FK chunks with "
              + std::to_string(chunk_size) + " rotations each");

    // Initialize cache: [chunk_idx][rotation] -> rotated_data
    fk_rotated_keys_cache_.resize(num_chunks);

    for (size_t chunk_idx = 0; chunk_idx < num_chunks; ++chunk_idx) {
        fk_rotated_keys_cache_[chunk_idx].resize(chunk_size);

        // Get the original data for this chunk
        const auto& original_data = fk_chunks[chunk_idx]->values;

        // Precompute all rotations for this chunk
        fk_rotated_keys_cache_[chunk_idx][0] = original_data;  // Original, no rotation

        auto start_time = std::chrono::high_resolution_clock::now();
        for (size_t rot = 1; rot < chunk_size; ++rot) {
            // Simulate rotation by shifting the data
            auto prev_chunk = std::make_shared<PlainColumnChunk>(fk_rotated_keys_cache_[chunk_idx][rot - 1]);
            auto rotated_chunk = plainEvalRotate(prev_chunk, 1);
            trackEvalRotate(); // Track FK key rotation
            fk_rotated_keys_cache_[chunk_idx][rot] = rotated_chunk->values;
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        debugPrint("[Precompute] FK chunk " + std::to_string(chunk_idx) + " completed in "
                  + std::to_string(total_duration.count()) + " ms");
    }
}

std::shared_ptr<PlainColumnTable> ColumnKeyedJoin::performJoin(const size_t chunk_size) {
    debugPrint("[Column Keyed Join] Starting join with " + std::to_string(fk_rotated_keys_cache_.size())
              + " FK chunks");
    debugPrint("[Column Keyed Join] FK join key: " + fk_join_key_name_);
    debugPrint("[Column Keyed Join] PK join key: " + pk_join_key_name_);
    debugPrint("[Column Keyed Join] Foreign key input: " + std::to_string(foreign_key_input_));

    // Determine FK and PK tables
    auto fk_table = (foreign_key_input_ == 0) ? lhs_table_ : rhs_table_;
    auto pk_table = (foreign_key_input_ == 0) ? rhs_table_ : lhs_table_;

    debugPrint("[Column Keyed Join] FK table row count: " + std::to_string(fk_table->getRowCount()));
    debugPrint("[Column Keyed Join] PK table row count: " + std::to_string(pk_table->getRowCount()));
    std::string fk_cols = "[Column Keyed Join] FK table columns: ";
    for (const auto& col : fk_table->getColumnNames()) {
        fk_cols += col + " ";
    }
    debugPrint(fk_cols);
    std::string pk_cols = "[Column Keyed Join] PK table columns: ";
    for (const auto& col : pk_table->getColumnNames()) {
        pk_cols += col + " ";
    }
    debugPrint(pk_cols);

    // Set output schema same as FK table schema first, then add PK columns
    QuerySchema output_schema = fk_table->getSchema();
    SortDefinition sort_definition = this->sort_definition_;

    // Add PK columns to schema (excluding the join key)
    const auto& pk_schema = pk_table->getSchema();
    int fk_field_count = fk_table->getSchema().getFieldCount();
    int pk_field_idx = 0;
    for (size_t i = 0; i < pk_schema.getFieldCount(); ++i) {
        const auto& field = pk_schema.getField(i);
        if (field.getName() != pk_join_key_name_) {
            QueryFieldDesc adjusted_field(fk_field_count + pk_field_idx,
                                          field.getName(),
                                          field.getTableName(),
                                          field.getType(),
                                          field.getStringLength());
            output_schema.putField(adjusted_field);
            pk_field_idx++;
        }
    }

    // Create output table
    uint32_t output_tuple_cnt = fk_table->getRowCount();
    auto output = std::make_shared<PlainColumnTable>(output_schema, output_tuple_cnt);

    debugPrint("[Column Keyed Join] Created output table with " + std::to_string(output_tuple_cnt) + " rows");
    debugPrint("[Column Keyed Join] Output schema field count: " + std::to_string(output_schema.getFieldCount()));

    // Initialize output table structure
    debugPrint("[Column Keyed Join] Adding FK columns to output...");
    for (const auto& col_name : fk_table->getColumnNames()) {
        debugPrint("  [Column Keyed Join] Adding FK column: " + col_name);
        addColumnToOutput(output, col_name, fk_table, chunk_size);
    }

    debugPrint("[Column Keyed Join] Adding PK columns to output...");
    for (const auto& col_name : pk_table->getColumnNames()) {
        if (col_name != pk_join_key_name_ && col_name != "dummy_tag") {
            addColumnToOutput(output, col_name, pk_table, chunk_size);

            auto output_col = output->getPlainColumn(col_name);
            if (output_col) {
                for (size_t chunk_idx = 0; chunk_idx < output_col->getPlainChunks().size(); ++chunk_idx) {
                    std::vector<double> zero_data(chunk_size, 0.0);
                    std::vector<PlainField> zero_fields;
                    zero_fields.reserve(zero_data.size());
                    for (double val : zero_data) {
                        zero_fields.emplace_back(FieldType::FLOAT, static_cast<float>(val));
                    }
                    output_col->getPlainChunks()[chunk_idx]->values = zero_fields;
                }
            }
        }
    }

    // Initialize matched flag chunks
    debugPrint("[Column Keyed Join] Initializing matched flag chunks...");
    std::vector<std::vector<PlainField>> matched_flag_chunks;
    matched_flag_chunks.resize(fk_rotated_keys_cache_.size());
    for (size_t fk_chunk_idx = 0; fk_chunk_idx < fk_rotated_keys_cache_.size(); ++fk_chunk_idx) {
        matched_flag_chunks[fk_chunk_idx].resize(chunk_size, PlainField(FieldType::FLOAT, 0.0f));
    }
    debugPrint("[Column Keyed Join] Created " + std::to_string(matched_flag_chunks.size()) + " matched flag chunks");

    // Get PK join key column
    auto pk_key_column = pk_table->getPlainColumn(pk_join_key_name_);
    if (!pk_key_column) {
        throw std::runtime_error("PK join key column not found: " + pk_join_key_name_);
    }

    const auto& pk_key_chunks = pk_key_column->getPlainChunks();
    size_t pk_num_chunks = pk_key_chunks.size();

    debugPrint("[Column Keyed Join] PK key column   has " + std::to_string(pk_num_chunks) + " chunks");
    debugPrint("[Column Keyed Join] Starting join with " + std::to_string(pk_num_chunks) + " PK chunks and "
              + std::to_string(fk_rotated_keys_cache_.size()) + " FK chunks");
    debugPrint("[Column Keyed Join] Chunk size: " + std::to_string(chunk_size));

    for (size_t pk_chunk_idx = 0; pk_chunk_idx < pk_num_chunks; ++pk_chunk_idx) {
        debugPrint("[Column Keyed Join] Processing PK chunk " + std::to_string(pk_chunk_idx) + "/" + std::to_string(pk_num_chunks));
        auto pk_key = pk_key_chunks[pk_chunk_idx]->values;
        debugPrint("  [Column Keyed Join] PK key chunk size: " + std::to_string(pk_key.size()));
        if (debug_enabled_) {
            std::string pk_debug = "  [DEBUG] PK key chunk (all values): ";
            for (size_t i = 0; i < pk_key.size(); ++i) {
                switch (pk_key[i].getType()) {
                    case FieldType::INT:
                        pk_debug += std::to_string(pk_key[i].getValue<int32_t>()) + " ";
                        break;
                    case FieldType::LONG:
                        pk_debug += std::to_string(pk_key[i].getValue<int64_t>()) + " ";
                        break;
                    case FieldType::FLOAT:
                        pk_debug += std::to_string(pk_key[i].getValue<float>()) + " ";
                        break;
                    case FieldType::BOOL:
                        pk_debug += (pk_key[i].getValue<bool>() ? "true" : "false") + std::string(" ");
                        break;
                    default:
                        pk_debug += "? ";
                        break;
                }
            }
            debugPrint(pk_debug);
        }

        // Get PK payload columns for this chunk
        std::vector<std::vector<PlainField>> pk_payloads;
        debugPrint("  [Column Keyed Join] Getting PK payload columns...");
        for (const auto& col_name : pk_table->getColumnNames()) {
            if (col_name != pk_join_key_name_ && col_name != "dummy_tag") {
                auto pk_col = pk_table->getPlainColumn(col_name);
                if (pk_col && pk_chunk_idx < pk_col->getPlainChunks().size()) {
                    debugPrint("    [Column Keyed Join] Adding PK payload column: " + col_name);
                    pk_payloads.push_back(pk_col->getPlainChunks()[pk_chunk_idx]->values);
                } else {
                    debugPrint("    [Column Keyed Join] Skipping PK payload column: " + col_name + " (not found or chunk index out of range)");
                }
            }
        }
        debugPrint("  [Column Keyed Join] Got " + std::to_string(pk_payloads.size()) + " PK payload columns");

        // Get PK dummy tag for this chunk
        auto pk_dummy_col = pk_table->getPlainColumn("dummy_tag");
        std::vector<PlainField> pk_dummy;
        if (pk_dummy_col && pk_chunk_idx < pk_dummy_col->getPlainChunks().size()) {
            pk_dummy = pk_dummy_col->getPlainChunks()[pk_chunk_idx]->values;
            debugPrint("  [Column Keyed Join] Got PK dummy tag chunk with " + std::to_string(pk_dummy.size()) + " values");
        } else {
            pk_dummy.resize(chunk_size, PlainField(FieldType::FLOAT, 0.0f));
            debugPrint("  [Column Keyed Join] Created default PK dummy tag chunk with " + std::to_string(pk_dummy.size()) + " values");
        }

        for (size_t fk_chunk_idx = 0; fk_chunk_idx < fk_rotated_keys_cache_.size(); ++fk_chunk_idx) {
            debugPrint("  [Column Keyed Join] Processing FK chunk " + std::to_string(fk_chunk_idx) + "/"
                      + std::to_string(fk_rotated_keys_cache_.size()));
            debugPrint("    [Column Keyed Join] FK rotated keys cache has " + std::to_string(fk_rotated_keys_cache_[fk_chunk_idx].size()) + " rotations");

            for (size_t rot = 0; rot < chunk_size; ++rot) {
                debugPrint("    [Column Keyed Join] Processing rotation " + std::to_string(rot) + "/" + std::to_string(chunk_size));

                auto fk_key_rotated = fk_rotated_keys_cache_[fk_chunk_idx][rot];

                if (debug_enabled_) {
                    std::string fk_debug = "      [DEBUG] FK key rotated chunk (all values): ";
                    for (size_t i = 0; i < fk_key_rotated.size(); ++i) {
                        switch (fk_key_rotated[i].getType()) {
                            case FieldType::INT:
                                fk_debug += std::to_string(fk_key_rotated[i].getValue<int32_t>()) + " ";
                                break;
                            case FieldType::LONG:
                                fk_debug += std::to_string(fk_key_rotated[i].getValue<int64_t>()) + " ";
                                break;
                            case FieldType::FLOAT:
                                fk_debug += std::to_string(fk_key_rotated[i].getValue<float>()) + " ";
                                break;
                            case FieldType::BOOL:
                                fk_debug += (fk_key_rotated[i].getValue<bool>() ? "true" : "false") + std::string(" ");
                                break;
                            default:
                                fk_debug += "? ";
                                break;
                        }
                    }
                    debugPrint(fk_debug);
                }

                // Get FK dummy tag and rotate it
                auto fk_dummy_col = fk_table->getPlainColumn("dummy_tag");
                std::vector<PlainField> fk_dummy_rotated;
                if (fk_dummy_col) {
                    auto fk_dummy = fk_dummy_col->getPlainChunks()[fk_chunk_idx]->values;
                    if (rot == 0) {
                        fk_dummy_rotated = fk_dummy;
                    } else {
                        auto fk_dummy_chunk = std::make_shared<PlainColumnChunk>(fk_dummy);
                        auto rotated_chunk =  plainRotateByBinaryDecomposition(fk_dummy_chunk, rot, chunk_size);
                        trackEvalRotate(); // Track FK dummy tag rotation

                        fk_dummy_rotated = rotated_chunk->values;
                    }
                } else throw std::runtime_error("Missing 'dummy_tag' in FK.");

                std::vector<PlainField> key_equal(chunk_size);
                std::vector<PlainField> pk_not_dummy(chunk_size);
                std::vector<PlainField> fk_not_dummy(chunk_size);
                std::vector<PlainField> match_mask(chunk_size);

                // Count matches for debugging
                size_t matches_found = 0;

                // Create PlainColumnChunks for SIMD operations
                auto fk_key_rotated_chunk = std::make_shared<PlainColumnChunk>(fk_key_rotated);
                auto pk_key_chunk = std::make_shared<PlainColumnChunk>(pk_key);
                auto pk_dummy_chunk = std::make_shared<PlainColumnChunk>(pk_dummy);
                auto fk_dummy_rotated_chunk = std::make_shared<PlainColumnChunk>(fk_dummy_rotated);

                // SIMD operations using the new functions
                auto key_equal_chunk = plainCompEqual(fk_key_rotated_chunk, pk_key_chunk);
                auto pk_not_dummy_chunk = plainCompNot(pk_dummy_chunk);
                auto fk_not_dummy_chunk = plainCompNot(fk_dummy_rotated_chunk);

                // Multiply for match mask: key_equal * pk_not_dummy * fk_not_dummy
                auto temp_chunk = plainEvalMult(pk_not_dummy_chunk, fk_not_dummy_chunk);
                trackEvalMult(); // Track first EvalMult: pk_not_dummy * fk_not_dummy
                trackDataFlowDepth("match_mask_temp", 1);
                
                auto match_mask_chunk = plainEvalMult(key_equal_chunk, temp_chunk);
                trackEvalMult(); // Track second EvalMult: key_equal * (pk_not_dummy * fk_not_dummy)
                trackDataFlowDepth("match_mask", 2);

                // Convert back to vectors
                key_equal = key_equal_chunk->values;
                pk_not_dummy = pk_not_dummy_chunk->values;
                fk_not_dummy = fk_not_dummy_chunk->values;
                match_mask = match_mask_chunk->values;

                // Debug pk dummy flag
                if (debug_enabled_) {
                    std::string pk_dummy_debug = "      [DEBUG] PK DUMMY (all values): ";
                    auto pk_dummy_values = pk_dummy_chunk->values;
                    for (size_t i = 0; i < pk_dummy_values.size(); ++i) {
                        switch (pk_dummy_values[i].getType()) {
                            case FieldType::INT:
                                pk_dummy_debug += std::to_string(pk_dummy_values[i].getValue<int32_t>()) + " ";
                                break;
                            case FieldType::LONG:
                                pk_dummy_debug += std::to_string(pk_dummy_values[i].getValue<int64_t>()) + " ";
                                break;
                            case FieldType::FLOAT:
                                pk_dummy_debug += std::to_string(pk_dummy_values[i].getValue<float>()) + " ";
                                break;
                            case FieldType::BOOL:
                                pk_dummy_debug += (pk_dummy_values[i].getValue<bool>() ? "true" : "false") + std::string(" ");
                                break;
                            default:
                                pk_dummy_debug += "? ";
                                break;
                        }
                    }
                    debugPrint(pk_dummy_debug);
                }

                // Debug fk dummy flag
                if (debug_enabled_) {
                    std::string fk_dummy_debug = "      [DEBUG] FK ROTATED DUMMY  (all values): ";
                    auto fk_dummy_rotated_values = fk_dummy_rotated_chunk->values;
                    for (size_t i = 0; i < fk_dummy_rotated_values.size(); ++i) {
                        switch (fk_dummy_rotated_values[i].getType()) {
                            case FieldType::INT:
                                fk_dummy_debug += std::to_string(fk_dummy_rotated_values[i].getValue<int32_t>()) + " ";
                                break;
                            case FieldType::LONG:
                                fk_dummy_debug += std::to_string(fk_dummy_rotated_values[i].getValue<int64_t>()) + " ";
                                break;
                            case FieldType::FLOAT:
                                fk_dummy_debug += std::to_string(fk_dummy_rotated_values[i].getValue<float>()) + " ";
                                break;
                            case FieldType::BOOL:
                                fk_dummy_debug += (fk_dummy_rotated_values[i].getValue<bool>() ? "true" : "false") + std::string(" ");
                                break;
                            default:
                                fk_dummy_debug += "? ";
                                break;
                        }
                    }
                    debugPrint(fk_dummy_debug);
                }

                // Debug match flag
                if (debug_enabled_) {
                    std::string match_debug = "      [DEBUG] Match mask (all values): ";
                    for (size_t i = 0; i < match_mask.size(); ++i) {
                            switch (match_mask[i].getType()) {
                                case FieldType::INT:
                                    match_debug += std::to_string(match_mask[i].getValue<int32_t>()) + " ";
                                    break;
                                case FieldType::LONG:
                                    match_debug += std::to_string(match_mask[i].getValue<int64_t>()) + " ";
                                    break;
                                case FieldType::FLOAT:
                                    match_debug += std::to_string(match_mask[i].getValue<float>()) + " ";
                                    break;
                                case FieldType::BOOL:
                                    match_debug += (match_mask[i].getValue<bool>() ? "true" : "false") + std::string(" ");
                                    break;
                                default:
                                    match_debug += "? ";
                                    break;
                            }
                    }
                    debugPrint(match_debug);
                }

                // Calculate back-rotation amount
                int back_rotation = static_cast<int>(chunk_size - rot);

                // Apply match mask to PK payloads and accumulate to output
                size_t payload_idx = 0;

                for (const auto& col_name : pk_table->getColumnNames()) {
                    if (col_name != pk_join_key_name_ && col_name != "dummy_tag") {
                        auto output_col = output->getPlainColumn(col_name);

                        if (!output_col) continue;

                        debugPrint("          [Column Keyed Join] Processing payload column: " + col_name + " (idx: " + std::to_string(payload_idx) + ")");

                        // SIMD-style payload masking
                        auto match_mask_chunk = std::make_shared<PlainColumnChunk>(match_mask);
                        auto payload_chunk = std::make_shared<PlainColumnChunk>(pk_payloads[payload_idx]);
                        auto masked_payload_chunk = plainEvalMult(match_mask_chunk, payload_chunk);
                        trackEvalMult(); // Track payload masking: match_mask * payload
                        trackDataFlowDepth("payload_" + col_name, 3); // match_mask (depth 2) * payload (depth 0) = depth 3
                        std::vector<PlainField> masked_payload = masked_payload_chunk->values;

                        // Debug payload
                        if (debug_enabled_) {
                            std::string payload_debug = "          [DEBUG] Original payload (all values): ";
                            for (size_t i = 0; i < pk_payloads[payload_idx].size(); ++i) {
                                switch (pk_payloads[payload_idx][i].getType()) {
                                    case FieldType::INT:
                                        payload_debug += std::to_string(pk_payloads[payload_idx][i].getValue<int32_t>()) + " ";
                                        break;
                                    case FieldType::LONG:
                                        payload_debug += std::to_string(pk_payloads[payload_idx][i].getValue<int64_t>()) + " ";
                                        break;
                                    case FieldType::FLOAT:
                                        payload_debug += std::to_string(pk_payloads[payload_idx][i].getValue<float>()) + " ";
                                        break;
                                    case FieldType::BOOL:
                                        payload_debug += (pk_payloads[payload_idx][i].getValue<bool>() ? "true" : "false") + std::string(" ");
                                        break;
                                    default:
                                        payload_debug += "? ";
                                        break;
                                }
                            }
                            debugPrint(payload_debug);
                        }

                        if (debug_enabled_) {
                            std::string masked_payload_debug = "          [DEBUG] Masked payload (all values): ";
                            for (size_t i = 0; i < masked_payload.size(); ++i) {
                                    switch (masked_payload[i].getType()) {
                                        case FieldType::INT:
                                            masked_payload_debug += std::to_string(masked_payload[i].getValue<int32_t>()) + " ";
                                            break;
                                        case FieldType::LONG:
                                            masked_payload_debug += std::to_string(masked_payload[i].getValue<int64_t>()) + " ";
                                            break;
                                        case FieldType::FLOAT:
                                            masked_payload_debug += std::to_string(masked_payload[i].getValue<float>()) + " ";
                                            break;
                                        case FieldType::BOOL:
                                            masked_payload_debug += (masked_payload[i].getValue<bool>() ? "true" : "false") + std::string(" ");
                                            break;
                                        default:
                                            masked_payload_debug += "? ";
                                            break;
                                    }
                            }
                            debugPrint(masked_payload_debug);
                        }

                        // Back-rotate the payload using SIMD function
                        std::vector<PlainField> payload_back_rotated;
                        if (rot == 0) {
                            payload_back_rotated = masked_payload;
                        } else {
                            auto masked_payload_chunk = std::make_shared<PlainColumnChunk>(masked_payload);
                            auto rotated_chunk = plainRotateByBinaryDecomposition(masked_payload_chunk, back_rotation, chunk_size);
                            trackEvalRotate(); // Track payload back-rotation
                            payload_back_rotated = rotated_chunk->values;
                        }

                        if (debug_enabled_) {
                            std::string rotated_payload_debug = "          [DEBUG] Rotated Masked payload (all values): ";
                            for (size_t i = 0; i < masked_payload.size(); ++i) {
                                switch (payload_back_rotated[i].getType()) {
                                    case FieldType::INT:
                                        rotated_payload_debug += std::to_string(payload_back_rotated[i].getValue<int32_t>()) + " ";
                                        break;
                                    case FieldType::LONG:
                                        rotated_payload_debug += std::to_string(payload_back_rotated[i].getValue<int64_t>()) + " ";
                                        break;
                                    case FieldType::FLOAT:
                                        rotated_payload_debug += std::to_string(payload_back_rotated[i].getValue<float>()) + " ";
                                        break;
                                    case FieldType::BOOL:
                                        rotated_payload_debug += (payload_back_rotated[i].getValue<bool>() ? "true" : "false") + std::string(" ");
                                        break;
                                    default:
                                        rotated_payload_debug += "? ";
                                        break;
                                }
                            }
                            debugPrint(rotated_payload_debug);
                        }

                        // SIMD-style accumulation
                        auto& current_output = output_col->getPlainChunks()[fk_chunk_idx]->values;
                        auto current_chunk = std::make_shared<PlainColumnChunk>(current_output);

//                        // Ensure payload size matches current chunk size
//                        std::vector<PlainField> sized_payload = payload_back_rotated;
//                        if (sized_payload.size() > current_output.size()) {
//                            sized_payload.resize(current_output.size());
//                        } else if (sized_payload.size() < current_output.size()) {
//                            // Pad with zeros if payload is smaller
//                            sized_payload.resize(current_output.size(), PlainField(FieldType::FLOAT, 0.0f));
//                        }

                        auto rotated_payload_chunk = std::make_shared<PlainColumnChunk>(payload_back_rotated);
                        auto sum_chunk = plainEvalAdd(current_chunk, rotated_payload_chunk);
                        // Note: plainEvalAdd does NOT increase multiplicative depth
                        // The output maintains the depth of the highest input (depth 3)
                        trackDataFlowDepth("output_" + col_name, 3);
                        current_output = sum_chunk->values;

                        if (debug_enabled_) {
                            std::string current_output_debug = "          [DEBUG] Current Output (all values): ";
                            for (size_t i = 0; i < current_output.size(); ++i) {
                                switch (current_output[i].getType()) {
                                    case FieldType::INT:
                                        current_output_debug += std::to_string(current_output[i].getValue<int32_t>()) + " ";
                                        break;
                                    case FieldType::LONG:
                                        current_output_debug += std::to_string(current_output[i].getValue<int64_t>()) + " ";
                                        break;
                                    case FieldType::FLOAT:
                                        current_output_debug += std::to_string(current_output[i].getValue<float>()) + " ";
                                        break;
                                    case FieldType::BOOL:
                                        current_output_debug += (current_output[i].getValue<bool>() ? "true" : "false") + std::string(" ");
                                        break;
                                    default:
                                        current_output_debug += "? ";
                                        break;
                                }
                            }
                            debugPrint(current_output_debug);
                        }

                        if (rot == 0) {
                            debugPrint("            [Column Keyed Join] Accumulated payload to output column: " + col_name);
                        }

                        payload_idx++;
                    }
                }

                // Update matched flag chunks using SIMD functions
                std::vector<PlainField> mask_back_rotated;
                if (rot == 0) {
                    mask_back_rotated = match_mask;
                } else {
                    auto match_mask_chunk = std::make_shared<PlainColumnChunk>(match_mask);
                    auto rotated_chunk = plainRotateByBinaryDecomposition(match_mask_chunk, back_rotation, chunk_size);
                    trackEvalRotate(); // Track match flag back-rotation
                    mask_back_rotated = rotated_chunk->values;
                }

                // SIMD-style matched flag updates (OR operation)
                auto current_flags_chunk = std::make_shared<PlainColumnChunk>(matched_flag_chunks[fk_chunk_idx]);
                auto new_flags_chunk = std::make_shared<PlainColumnChunk>(mask_back_rotated);
                auto updated_flags_chunk = plainCompOr(current_flags_chunk, new_flags_chunk);
                matched_flag_chunks[fk_chunk_idx] = updated_flags_chunk->values;
            }
        }
    }

    // Final dummy tag calculation
    debugPrint("[Column Keyed Join] Computing final dummy tags for " + std::to_string(fk_rotated_keys_cache_.size()) + " FK chunks");
    for (size_t fk_chunk_idx = 0; fk_chunk_idx < fk_rotated_keys_cache_.size(); ++fk_chunk_idx) {
        debugPrint("  [Column Keyed Join] Processing final dummy tag for FK chunk " + std::to_string(fk_chunk_idx));
        auto dummy_col = output->getPlainColumn("dummy_tag");
        if (dummy_col && fk_chunk_idx < dummy_col->getPlainChunks().size()) {
            auto& fk_dummy = dummy_col->getPlainChunks()[fk_chunk_idx]->values;

            // SIMD-style final dummy calculation: OR(fk_dummy, NOT(matched_flag))
            auto fk_dummy_chunk = std::make_shared<PlainColumnChunk>(fk_dummy);
            auto matched_flag_chunk = std::make_shared<PlainColumnChunk>(matched_flag_chunks[fk_chunk_idx]);

            // NOT(matched_flag)
            auto not_matched_flag_chunk = plainCompNot(matched_flag_chunk);

            // OR(fk_dummy, NOT(matched_flag))
            auto final_dummy_chunk = plainCompOr(fk_dummy_chunk, not_matched_flag_chunk);

            // Update dummy tags
            fk_dummy = final_dummy_chunk->values;
            debugPrint("    [Column Keyed Join] Updated dummy tag for FK chunk " + std::to_string(fk_chunk_idx));
        } else {
            debugPrint("    [Column Keyed Join] No dummy tag column found for FK chunk " + std::to_string(fk_chunk_idx));
        }
    }

    debugPrint("[Column Keyed Join] Join completed successfully!");
    return output;
}

void ColumnKeyedJoin::addColumnToOutput(std::shared_ptr<PlainColumnTable>& output,
                                        const std::string& col_name,
                                        const std::shared_ptr<PlainColumnTable>& source_table,
                                        const size_t chunk_size) {
    auto source_col = source_table->getPlainColumn(col_name);
    if (source_col) {
        auto new_col = std::make_shared<PlainColumn>(col_name);

        // For PK-FK join, we need to handle row count mismatch
        // The output table has FK row count, but PK columns might have different row counts
        size_t output_row_count = output->getRowCount();
        size_t source_row_count = source_col->getRowCount();

        debugPrint("    [Column Keyed Join] Adding column '" + col_name + "' with " + std::to_string(source_row_count)
                  + " rows to output table with " + std::to_string(output_row_count) + " rows");

        // Deep copy chunks and pad/truncate as needed
        size_t current_row = 0;
        for (const auto& chunk : source_col->getPlainChunks()) {
            auto new_chunk = std::make_shared<PlainColumnChunk>(chunk->values);
            new_col->addChunk(new_chunk);
            current_row += chunk->values.size();
        }

        // If we need more rows to match output table size, pad with zeros
        if (current_row < output_row_count) {
            size_t remaining_rows = output_row_count - current_row;
            debugPrint("    [Column Keyed Join] Padding column '" + col_name + "' with " + std::to_string(remaining_rows) + " zero rows");

            // Create additional chunks with zero values to reach the required row count
            while (remaining_rows > 0) {
                size_t chunk_rows = std::min(remaining_rows, chunk_size);
                std::vector<PlainField> zero_chunk(chunk_rows, PlainField(FieldType::FLOAT, 0.0f));
                auto padding_chunk = std::make_shared<PlainColumnChunk>(zero_chunk);
                new_col->addChunk(padding_chunk);
                remaining_rows -= chunk_rows;
            }
        }

        output->addColumn(col_name, new_col);
        debugPrint("    [Column Keyed Join] Successfully added column '" + col_name + "' with " + std::to_string(new_col->getRowCount()) + " rows");
    }
}

OperatorType ColumnKeyedJoin::getType() const {
    return OperatorType::COLUMN_KEYED_NESTED_LOOP_JOIN;
}



// Per-data-flow depth tracking functions
void ColumnKeyedJoin::resetDataFlowDepths() {
    data_flow_depths_.clear();
    max_data_flow_depths_.clear();
}

void ColumnKeyedJoin::trackDataFlowDepth(const std::string& flow_name, uint32_t depth) {
    data_flow_depths_[flow_name] = depth;
    
    // Update maximum depth for this flow
    auto it = max_data_flow_depths_.find(flow_name);
    if (it == max_data_flow_depths_.end() || depth > it->second) {
        max_data_flow_depths_[flow_name] = depth;
    }
}

uint32_t ColumnKeyedJoin::getMaxDepthForDataFlow(const std::string& flow_name) {
    auto it = max_data_flow_depths_.find(flow_name);
    return (it != max_data_flow_depths_.end()) ? it->second : 0;
}