#include "fhe_keyed_join.h"
#include <util/crypto_manager/fhe_manager.h>
#include <util/fhe/fhe_comparator.h>
#include <query_table/columnar/fhe_column.h>
#include <query_table/columnar/fhe_column_chunk.h>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <iostream>

using namespace vaultdb;
using namespace lbcrypto;

FheKeyedJoin::FheKeyedJoin(std::shared_ptr<FheColumnTable> lhs,
                           std::shared_ptr<FheColumnTable> rhs,
                           const SIMDFheGenericExpression& join_condition,
                           const std::string& fk_join_key,
                           const std::string& pk_join_key,
                           int foreign_key_input)
        : ColumnOperator<void>(SortDefinition{}, lhs->getRowCount()),  // required base init
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

void FheKeyedJoin::setPrecomputedCache(const std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>>& cache) {
    fk_rotated_keys_cache_ = cache;
    precomputed_cache_provided_ = true;
    std::cout << "[FheKeyedJoin] Precomputed cache injected with " << cache.size() << " chunks" << std::endl;
}

void FheKeyedJoin::setPlaintextCacheAndEncrypt(const std::vector<std::vector<std::vector<PlainField>>>& plaintext_cache) {
    FheManager& fhe_manager = FheManager::getInstance();
    auto cc = fhe_manager.getRealCryptoContext();
    auto pk = fhe_manager.getRealPublicKey();

    std::cout << "[FheKeyedJoin] Converting plaintext cache to FHE ciphertexts" << std::endl;

    size_t num_chunks = plaintext_cache.size();
    size_t chunk_size = plaintext_cache[0].size();

    fk_rotated_keys_cache_.resize(num_chunks);

    for (size_t chunk_idx = 0; chunk_idx < num_chunks; ++chunk_idx) {
        fk_rotated_keys_cache_[chunk_idx].resize(chunk_size);

        auto start_time = std::chrono::high_resolution_clock::now();

        for (size_t rot = 0; rot < chunk_size; ++rot) {
            // Convert PlainField vector to int64_t for BFV packed plaintext
            std::vector<int64_t> int_values;
            int_values.reserve(plaintext_cache[chunk_idx][rot].size());

            for (const auto& field : plaintext_cache[chunk_idx][rot]) {
                switch (field.getType()) {
                    case FieldType::BOOL:
                        int_values.push_back(field.getValue<bool>() ? 1 : 0);
                        break;
                    case FieldType::INT:
                        int_values.push_back(static_cast<int64_t>(field.getValue<int32_t>()));
                        break;
                    case FieldType::LONG:
                        int_values.push_back(field.getValue<int64_t>());
                        break;
                    case FieldType::FLOAT:
                        int_values.push_back(static_cast<int64_t>(field.getValue<float>()));
                        break;
                    default:
                        int_values.push_back(0);
                        break;
                }
            }

            // Pad to chunk_size if needed
            while (int_values.size() < chunk_size) {
                int_values.push_back(0);
            }

            // Encrypt (BFV)
            auto pt = cc->MakePackedPlaintext(int_values);
            fk_rotated_keys_cache_[chunk_idx][rot] = cc->Encrypt(pk, pt);

            if (rot % 50 == 0) {
                auto current_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
                std::cout << "[FheKeyedJoin Encrypt] FK chunk " << chunk_idx << ": " << rot
                          << " rotations encrypted in " << duration.count() << " ms" << std::endl;
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        std::cout << "[FheKeyedJoin Encrypt] FK chunk " << chunk_idx << " encryption completed in "
                  << total_duration.count() << " ms" << std::endl;
    }

    precomputed_cache_provided_ = true;
    std::cout << "[FheKeyedJoin] Plaintext cache converted and encrypted with " << num_chunks << " chunks" << std::endl;
}

std::shared_ptr<ColumnTableBase<void>> FheKeyedJoin::runSelf() {
    // Precompute rotated FK keys for caching (skip if precomputed cache provided)
    if (!precomputed_cache_provided_) {
        precomputeRotatedFKKeys();
    } else {
        std::cout << "[FheKeyedJoin] Using precomputed cache, skipping precomputation" << std::endl;
    }

    // Perform the join
    auto result = performJoin();

    this->output_ = result;
    return this->output_;
}


void FheKeyedJoin::precomputeRotatedFKKeys() {
    FheManager& fhe_manager = FheManager::getInstance();
    auto cc = fhe_manager.getRealCryptoContext();

    // Determine which table is the FK table
    auto fk_table = (foreign_key_input_ == 0) ? lhs_table_ : rhs_table_;
    auto fk_column = fk_table->getFheColumn(fk_join_key_name_);

    if (!fk_column) {
        throw std::runtime_error("FK join key column not found: " + fk_join_key_name_);
    }

    const auto& fk_chunks = fk_column->getFheChunks();
    size_t num_chunks = fk_chunks.size();
    size_t chunk_size = fhe_manager.getBFVBatchSize();

    fk_rotated_keys_cache_.resize(num_chunks);

    for (size_t chunk_idx = 0; chunk_idx < num_chunks; ++chunk_idx) {
        fk_rotated_keys_cache_[chunk_idx].resize(chunk_size);

        std::cout << "[Precompute] FK chunk " << chunk_idx << ": starting " << chunk_size << " rotations" << std::endl;

        auto start_time = std::chrono::high_resolution_clock::now();

        fk_rotated_keys_cache_[chunk_idx][0] = fk_chunks[chunk_idx]->ciphertext();
        for (size_t rot = 1; rot < chunk_size; ++rot) {
            auto rot_start = std::chrono::high_resolution_clock::now();

            fk_rotated_keys_cache_[chunk_idx][rot] =
                    cc->EvalRotate(fk_rotated_keys_cache_[chunk_idx][rot - 1], 1);

            // Log every 100 items
            if (rot % 100 == 0) {
                auto rot_end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(rot_end - start_time).count();
                std::cout << "[Precompute] FK chunk " << chunk_idx
                          << ": " << rot << " rotations done in "
                          << duration << " ms" << std::endl;
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto total = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "[Precompute] FK chunk " << chunk_idx << ": total time " << total << " ms" << std::endl;
    }
}

void FheKeyedJoin::precomputeFastRotatedFKKeys() {
    FheManager& fhe_manager = FheManager::getInstance();
    auto cc = fhe_manager.getRealCryptoContext();

    // Determine which table is the FK table
    auto fk_table = (foreign_key_input_ == 0) ? lhs_table_ : rhs_table_;
    auto fk_column = fk_table->getFheColumn(fk_join_key_name_);

    if (!fk_column) {
        throw std::runtime_error("FK join key column not found: " + fk_join_key_name_);
    }

    const auto& fk_chunks = fk_column->getFheChunks();
    size_t num_chunks = fk_chunks.size();
    size_t chunk_size = fhe_manager.getBFVBatchSize();
    uint32_t m = cc->GetCyclotomicOrder();  // required by EvalFastRotation

    fk_rotated_keys_cache_.resize(num_chunks);

    for (size_t chunk_idx = 0; chunk_idx < num_chunks; ++chunk_idx) {
        auto ct = fk_chunks[chunk_idx]->ciphertext();

        std::cout << "[FastPrecompute] FK chunk " << chunk_idx << ": digit decomposition..." << std::endl;
        auto start_time = std::chrono::high_resolution_clock::now();

        // Step 1: Digit decomposition (only once!)
        auto digits = cc->EvalFastRotationPrecompute(ct);

        fk_rotated_keys_cache_[chunk_idx].resize(chunk_size);
        fk_rotated_keys_cache_[chunk_idx][0] = ct;

        // Step 2: Fast rotation using the digits
        for (size_t rot = 1; rot < chunk_size; ++rot) {
            fk_rotated_keys_cache_[chunk_idx][rot] =
                    cc->EvalFastRotation(ct, rot, m, digits);

            if (rot % 100 == 0) {
                auto now = std::chrono::high_resolution_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
                std::cout << "[FastPrecompute] FK chunk " << chunk_idx
                          << ": " << rot << " fast rotations done in "
                          << elapsed << " ms" << std::endl;
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto total = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        std::cout << "[FastPrecompute] FK chunk " << chunk_idx << ": total time " << total << " ms" << std::endl;
    }
}

std::shared_ptr<FheColumnTable> FheKeyedJoin::performJoin() {
    FheManager& fhe_manager = FheManager::getInstance();
    auto cc = fhe_manager.getRealCryptoContext();
    size_t chunk_size = fhe_manager.getBFVBatchSize();

    auto fk_table = (foreign_key_input_ == 0) ? lhs_table_ : rhs_table_;
    auto pk_table = (foreign_key_input_ == 0) ? rhs_table_ : lhs_table_;

    QuerySchema output_schema = fk_table->getSchema();
    SortDefinition sort_definition = this->sort_definition_;

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

    uint32_t output_tuple_cnt = fk_table->getRowCount();
    auto output = std::make_shared<FheColumnTable>(output_schema, output_tuple_cnt);

    for (const auto& col_name : fk_table->getColumnNames()) {
        addColumnToOutput(output, col_name, fk_table);
    }

    size_t fk_chunk_count = output->getFheColumn(fk_table->getColumnNames()[0])->getFheChunks().size();

    // Add PK columns (excluding join key and dummy_tag), and initialize
    for (const auto& col_name : pk_table->getColumnNames()) {
        if (col_name != pk_join_key_name_ && col_name != "dummy_tag") {
            addColumnToOutput(output, col_name, pk_table);

            auto output_col = output->getFheColumn(col_name);
            if (output_col) {
                auto& chunks = output_col->getMutableFheChunks();
                chunks.resize(fk_chunk_count);

                for (size_t chunk_idx = 0; chunk_idx < fk_chunk_count; ++chunk_idx) {
                    std::vector<int64_t> zeros(fhe_manager.getBFVBatchSize(), 0);
                    auto zero_pt = cc->MakePackedPlaintext(zeros);
                    auto zero_ct = cc->Encrypt(fhe_manager.getRealPublicKey(), zero_pt);

                    // Fill empty slots with new empty FheColumnChunks
                    if (!chunks[chunk_idx]) {
                        auto new_chunk = std::make_shared<FheColumnChunk>();
                        new_chunk->ciphertext() = zero_ct;
                        chunks[chunk_idx] = new_chunk;
                    } else {
                        auto concrete_chunk = std::dynamic_pointer_cast<FheColumnChunk>(chunks[chunk_idx]);
                        concrete_chunk->ciphertext() = zero_ct;
                    }
                }
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> matched_flag_chunks(fk_rotated_keys_cache_.size());
    std::vector<int64_t> zeros(chunk_size, 0);
    auto zero_pt = cc->MakePackedPlaintext(zeros);
    for (size_t fk_chunk_idx = 0; fk_chunk_idx < fk_rotated_keys_cache_.size(); ++fk_chunk_idx) {
        matched_flag_chunks[fk_chunk_idx] = cc->Encrypt(fhe_manager.getRealPublicKey(), zero_pt);
    }

    auto pk_key_column = pk_table->getFheColumn(pk_join_key_name_);
    if (!pk_key_column) throw std::runtime_error("PK join key column not found: " + pk_join_key_name_);
    const auto& pk_key_chunks = pk_key_column->getFheChunks();
    size_t pk_num_chunks = pk_key_chunks.size();

    std::cout << "[FHE Join] Starting join with " << pk_num_chunks << " PK chunks and "
              << fk_rotated_keys_cache_.size() << " FK chunks" << std::endl;

    for (size_t pk_chunk_idx = 0; pk_chunk_idx < pk_num_chunks; ++pk_chunk_idx) {
        std::cout << "[FHE Join] Processing PK chunk " << pk_chunk_idx << std::endl;
        auto pk_key = pk_key_chunks[pk_chunk_idx]->ciphertext();

        std::map<std::string, std::vector<Ciphertext<DCRTPoly>>> pk_payloads;
        for (const auto& col_name : pk_table->getColumnNames()) {
            if (col_name != pk_join_key_name_ && col_name != "dummy_tag") {
                auto pk_col = pk_table->getFheColumn(col_name);
                if (!pk_col) throw std::runtime_error("Missing PK column: " + col_name);
                const auto& chunks = pk_col->getFheChunks();
                std::vector<Ciphertext<DCRTPoly>> ciphertexts;
                for (const auto& chunk : chunks) {
                    ciphertexts.push_back(chunk->ciphertext());
                }
                pk_payloads[col_name] = std::move(ciphertexts);
            }
        }

        auto pk_dummy_col = pk_table->getFheColumn("dummy_tag");
        Ciphertext<DCRTPoly> pk_dummy;
        if (pk_dummy_col && pk_chunk_idx < pk_dummy_col->getFheChunks().size())
            pk_dummy = pk_dummy_col->getFheChunks()[pk_chunk_idx]->ciphertext();
        else
            throw std::runtime_error("Missing 'dummy_tag' in PK.");

        for (size_t fk_chunk_idx = 0; fk_chunk_idx < fk_rotated_keys_cache_.size(); ++fk_chunk_idx) {
            for (size_t rot = 0; rot < chunk_size; ++rot) {
                auto fk_key_rotated = fk_rotated_keys_cache_[fk_chunk_idx][rot];
                auto fk_dummy_col = fk_table->getFheColumn("dummy_tag");
                Ciphertext<DCRTPoly> fk_dummy_rotated;
                if (fk_dummy_col) {
                    auto fk_dummy = fk_dummy_col->getFheChunks()[fk_chunk_idx]->ciphertext();
                    fk_dummy_rotated = (rot == 0) ? fk_dummy : rotateByBinaryDecomposition(cc, fk_dummy, rot, chunk_size);
                } else throw std::runtime_error("Missing 'dummy_tag' in FK.");

                auto key_equal = comp_equal(fk_key_rotated, pk_key);
                // FHE convention 1=valid: match when key equal and both rows valid
                auto match_mask = cc->EvalMult(key_equal, cc->EvalMult(pk_dummy, fk_dummy_rotated));

                std::cout << "    [DEBUG] Rotation: " << rot << ", MatchMask Level: " << match_mask->GetLevel() << std::endl;

                for (const auto& col_name : pk_table->getColumnNames()) {
                    if (col_name != pk_join_key_name_ && col_name != "dummy_tag") {
                        auto output_col = output->getFheColumn(col_name);
                        if (!output_col) continue;

                        auto pk_payload = pk_payloads[col_name][pk_chunk_idx];
                        std::cout << "        [DEBUG] PK payload level: " << pk_payload->GetLevel() << std::endl;
                        auto masked_payload = cc->EvalMult(match_mask, pk_payload);
                        auto payload_back_rotated = (rot == 0) ? masked_payload :
                                                    rotateByBinaryDecomposition(cc, masked_payload, rot, chunk_size);

                        auto current_output = Ciphertext<DCRTPoly>(output_col->getFheChunks()[fk_chunk_idx]->ciphertext());

                        // CRITICAL FIX: Direct addition, NO delta!
                        auto new_output = cc->EvalAdd(current_output, payload_back_rotated);

                        output_col->getFheChunks()[fk_chunk_idx]->ciphertext() = new_output;
                        //auto delta = cc->EvalSub(payload_back_rotated, current_output);

//                        auto mask_back_rotated = (rot == 0) ? match_mask :
//                                                 rotateByBinaryDecomposition(cc, match_mask, rot, chunk_size);
//
//                        std::cout << "        [DEBUG] Pre-mult levels: mask_back_rotated: "
//                                  << mask_back_rotated->GetLevel() << ", delta: " << delta->GetLevel() << std::endl;
//
//                        auto mask_delta = cc->EvalMult(mask_back_rotated, delta);
//                        auto new_output = cc->EvalAdd(current_output, mask_delta);
//                        output_col->getFheChunks()[fk_chunk_idx]->ciphertext() = new_output;

                        std::cout << "        [DEBUG] New output level: " << new_output->GetLevel() << std::endl;
                    }
                }

                auto flag_mask_back_rotated = (rot == 0) ? match_mask :
                                              rotateByBinaryDecomposition(cc, match_mask, rot, chunk_size);
                matched_flag_chunks[fk_chunk_idx] = comp_or(matched_flag_chunks[fk_chunk_idx], flag_mask_back_rotated);
            }
        }
    }

    for (size_t fk_chunk_idx = 0; fk_chunk_idx < fk_rotated_keys_cache_.size(); ++fk_chunk_idx) {
        auto dummy_col = output->getFheColumn("dummy_tag");
        if (!dummy_col) continue;

        auto fk_dummy = dummy_col->getFheChunks()[fk_chunk_idx]->ciphertext();
        auto matched_flag_binary = matched_flag_chunks[fk_chunk_idx];
        // FHE convention 1=valid: output valid only when FK was valid and matched
        auto final_dummy = cc->EvalMultAndRelinearize(fk_dummy, matched_flag_binary);
        dummy_col->getFheChunks()[fk_chunk_idx]->ciphertext() = final_dummy;
    }

    std::cout << "[FHE Join] Join completed successfully!" << std::endl;
    return output;
}


void FheKeyedJoin::addColumnToOutput(std::shared_ptr<FheColumnTable>& output,
                                     const std::string& col_name,
                                     const std::shared_ptr<FheColumnTable>& source_table) {
    // Add column to output (following reference keyed_join.cpp pattern)
    // Like reference: cloneRow(i, 0, lhs_table, i) or cloneRow(i, rhs_col_offset, rhs_table, i)
    auto source_col = source_table->getFheColumn(col_name);
    if (source_col) {
        auto new_col = std::make_shared<FheColumn>(col_name);

        // Deep copy chunks (like reference: cloneRow deep copy)
        for (const auto& chunk : source_col->getFheChunks()) {
            auto new_chunk = std::make_shared<FheColumnChunk>(
                    chunk->ciphertext(), chunk->q_params(), chunk->type_desc, chunk->size());
            new_col->addFheChunk(new_chunk);
        }

        output->addColumn(new_col);
    }
}



/**
 * Helper function to rotate by any amount using binary decomposition
 *
 * This function implements efficient rotation using power-of-2 decomposition.
 * Instead of requiring rotation keys for every possible rotation amount,
 * we only need keys for powers of 2 (1, 2, 4, 8, 16, ...).
 *
 * Example: To rotate by 13 positions:
 * - 13 = 8 + 4 + 1 (binary decomposition)
 * - Apply rotation by 8, then 4, then 1
 *
 * This dramatically reduces key generation time and memory usage
 * at the cost of slightly slower runtime rotations.
 */
Ciphertext<DCRTPoly> FheKeyedJoin::rotateByBinaryDecomposition(CryptoContext<DCRTPoly> cc,
                                                               const Ciphertext<DCRTPoly>& ct,
                                                               int rotation_amount,
                                                               uint32_t slot_size) {
    if (rotation_amount == 0) {
        return ct;
    }

    // Normalize to [0, slot_size)
    rotation_amount = rotation_amount % static_cast<int>(slot_size);
    if (rotation_amount < 0) {
        rotation_amount += static_cast<int>(slot_size);
    }

    // Decompose positive rotation into powers of 2
    // Start with a fresh copy to avoid modifying the original ciphertext
    Ciphertext<DCRTPoly> result(ct); // Use copy constructor to create a fresh copy
    for (int power = 1; power <= static_cast<int>(slot_size); power *= 2) {
        if (rotation_amount & power) {
            // Create a fresh copy for each rotation to avoid in-place modification
            result = cc->EvalRotate(result, power);
        }
    }

    return result;
}



OperatorType FheKeyedJoin::getType() const {
    return OperatorType::FHE_KEYED_NESTED_LOOP_JOIN;
}