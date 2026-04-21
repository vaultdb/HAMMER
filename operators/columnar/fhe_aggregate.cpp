    #include "operators/columnar/fhe_aggregate.h"
    #include <query_table/columnar/fhe_column.h>
    #include <query_table/columnar/fhe_column_chunk.h>
    #include <query_table/columnar/plain_column_chunk.h>
    #include <util/system_configuration.h>
    #include <util/crypto_manager/fhe_manager.h>
    #include <util/google_test_flags.h>
    #include <util/fhe/fhe_perf_counter.h>
    #include <util/fhe/fhe_query_plan.h>
    #include <util/fhe/fhe_thread_cost_model.h>
    #include <algorithm>
    #include <atomic>
    #include <cmath>
    #include <fstream>
    #include <iomanip>
    #include <iostream>
    #include <limits>
    #include <set>
    #include <stdexcept>
    #include <omp.h>
    #include <unordered_map>
    #include <vector>

    namespace vaultdb {
        using namespace lbcrypto;

        // Thread-local plaintext cache
        struct AggPtCacheKey { const void* cc; int64_t val; size_t slots;
            bool operator==(const AggPtCacheKey& o) const { return cc == o.cc && val == o.val && slots == o.slots; }
        };
        struct AggPtCacheKeyHash { size_t operator()(const AggPtCacheKey& k) const noexcept {
            size_t h = std::hash<const void*>{}(k.cc);
            h ^= std::hash<int64_t>{}(k.val) + 0x9e3779b9 + (h<<6) + (h>>2);
            h ^= std::hash<size_t>{}(k.slots) + 0x9e3779b9 + (h<<6) + (h>>2);
            return h;
        }};
        thread_local std::unordered_map<AggPtCacheKey, Plaintext, AggPtCacheKeyHash> tl_agg_pt_cache;

        inline Plaintext cachedAggUniformPt(const CryptoContext<DCRTPoly>& cc, int64_t val, size_t slots) {
            AggPtCacheKey key{cc.get(), val, slots};
            auto it = tl_agg_pt_cache.find(key);
            if (it != tl_agg_pt_cache.end()) return it->second;
            auto pt = cc->MakePackedPlaintext(std::vector<int64_t>(slots, val));
            tl_agg_pt_cache.emplace(key, pt);
            return pt;
        }

        // Thread-local zero-ciphertext cache
        struct ZeroCiCacheKey { const void* cc; const void* pk; size_t slots;
            bool operator==(const ZeroCiCacheKey& o) const { return cc == o.cc && pk == o.pk && slots == o.slots; }
        };
        struct ZeroCiCacheKeyHash { size_t operator()(const ZeroCiCacheKey& k) const noexcept {
            size_t h = std::hash<const void*>{}(k.cc);
            h ^= std::hash<const void*>{}(k.pk) + 0x9e3779b9 + (h<<6) + (h>>2);
            h ^= std::hash<size_t>{}(k.slots) + 0x9e3779b9 + (h<<6) + (h>>2);
            return h;
        }};
        thread_local std::unordered_map<ZeroCiCacheKey, Ciphertext<DCRTPoly>, ZeroCiCacheKeyHash> tl_zeroci_cache;

        inline Ciphertext<DCRTPoly> cachedZeroCi(const CryptoContext<DCRTPoly>& cc,
                                                  const PublicKey<DCRTPoly>& pk, size_t slots) {
            ZeroCiCacheKey key{cc.get(), pk.get(), slots};
            auto it = tl_zeroci_cache.find(key);
            if (it != tl_zeroci_cache.end()) return it->second;
            auto pt = cc->MakePackedPlaintext(std::vector<int64_t>(slots, 0));
            auto ci = cc->Encrypt(pk, pt);
            tl_zeroci_cache.emplace(key, ci);
            return ci;
        }

        // Thread-local target mask cache (single-hot-slot masks)
        struct TargetMaskKey { const void* cc; size_t ts; size_t slots;
            bool operator==(const TargetMaskKey& o) const { return cc == o.cc && ts == o.ts && slots == o.slots; }
        };
        struct TargetMaskKeyHash { size_t operator()(const TargetMaskKey& k) const noexcept {
            size_t h = std::hash<const void*>{}(k.cc);
            h ^= std::hash<size_t>{}(k.ts) + 0x9e3779b9 + (h<<6) + (h>>2);
            h ^= std::hash<size_t>{}(k.slots) + 0x9e3779b9 + (h<<6) + (h>>2);
            return h;
        }};
        thread_local std::unordered_map<TargetMaskKey, Plaintext, TargetMaskKeyHash> tl_targetmask_cache;

        inline Plaintext cachedTargetMask(const CryptoContext<DCRTPoly>& cc, size_t ts, size_t slots) {
            TargetMaskKey key{cc.get(), ts, slots};
            auto it = tl_targetmask_cache.find(key);
            if (it != tl_targetmask_cache.end()) return it->second;
            std::vector<int64_t> mask(slots, 0);
            mask[ts] = 1;
            auto pt = cc->MakePackedPlaintext(mask);
            tl_targetmask_cache.emplace(key, pt);
            return pt;
        }

        namespace {
            // Helper: Create PlainField from int64_t with proper type
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
                        throw std::runtime_error("FheAggregate: unsupported field type for PlainField creation");
                }
            }

            // Scale factor for decimal columns (6 decimal places); must match fhe_helpers and Party A.
            constexpr int kDecimalScaleFactor = 1000000;

            // Compute max absolute value of a numeric plain column (for RNS channel count).
            // For FLOAT (decimal), returns max after scaling by kDecimalScaleFactor so it matches encoded values.
            double computeMaxAbsVal(PlainColumnTable* plain_table, const std::string& col_name) {
                if (!plain_table) return 0.0;
                auto plain_col = plain_table->getPlainColumn(col_name);
                if (!plain_col) return 0.0;
                auto field_desc = plain_table->getSchema().getField(col_name);
                FieldType ft = field_desc.getType();
                if (ft != FieldType::INT && ft != FieldType::LONG && ft != FieldType::DATE && ft != FieldType::FLOAT) {
                    return 0.0;
                }
                double max_abs = 0.0;
                for (const auto& chunk : plain_col->getPlainChunks()) {
                    if (!chunk) continue;
                    for (const auto& f : chunk->getValues()) {
                        double abs_v;
                        if (ft == FieldType::INT) {
                            abs_v = static_cast<double>(std::abs(f.getValue<int32_t>()));
                        } else if (ft == FieldType::LONG || ft == FieldType::DATE) {
                            abs_v = static_cast<double>(std::llabs(f.getValue<int64_t>()));
                        } else {
                            // FLOAT: encoded as value * 100, so use scaled value for RNS bound
                            abs_v = std::fabs(static_cast<double>(f.getValue<float_t>()) * kDecimalScaleFactor);
                        }
                        if (abs_v > max_abs) max_abs = abs_v;
                    }
                }
                return max_abs;
            }

            struct ChannelOpStats {
                std::atomic<uint64_t> eval_add{0};
                std::atomic<uint64_t> eval_sub{0};
                std::atomic<uint64_t> eval_mult_ct_ct{0};
                std::atomic<uint64_t> eval_mult_ct_pt{0};
                std::atomic<uint64_t> eval_rotate{0};
                std::atomic<uint64_t> eval_relinearize{0};
                std::atomic<uint64_t> eval_modswitch{0};
                std::atomic<uint64_t> eval_keyswitch{0};
                std::atomic<uint64_t> eval_modreduce{0};
            };

            void printAggregateChannelStats(const std::vector<ChannelOpStats>& stats) {
                for (size_t ch = 0; ch < stats.size(); ++ch) {
                    const auto& s = stats[ch];
                    std::cout << "[OpStats FheAggregate] ch=" << ch
                              << " EvalAdd=" << s.eval_add.load(std::memory_order_relaxed)
                              << " EvalSub=" << s.eval_sub.load(std::memory_order_relaxed)
                              << " EvalMult(ct*ct)=" << s.eval_mult_ct_ct.load(std::memory_order_relaxed)
                              << " EvalMult(ct*pt)=" << s.eval_mult_ct_pt.load(std::memory_order_relaxed)
                              << " Rotate=" << s.eval_rotate.load(std::memory_order_relaxed)
                              << " Relinearize=" << s.eval_relinearize.load(std::memory_order_relaxed)
                              << " ModSwitch(explicit)=" << s.eval_modswitch.load(std::memory_order_relaxed)
                              << " KeySwitch(explicit+implied)=" << s.eval_keyswitch.load(std::memory_order_relaxed)
                              << " ModReduce(explicit+implied)=" << s.eval_modreduce.load(std::memory_order_relaxed)
                              << std::endl;
                }
            }
        }

        FheAggregate::FheAggregate(ColumnOperator<void>* child,
                                   const std::vector<ScalarAggregateDefinition>& aggregates,
                                   const std::vector<int32_t>& group_by_ordinals)
                : ColumnOperator<void>(SortDefinition{}, 0),
                  group_by_ordinals_(group_by_ordinals),
                  aggregate_definitions_(aggregates) {
            if (!child) {
                throw std::invalid_argument("FheAggregate: child operator is null");
            }
            setChild(child, 0);
            output_cardinality_ = child->getOutputCardinality();
            sort_definition_ = child->getSortOrder();

            // Parse-time schema propagation for downstream LogicalProject parsing.
            QuerySchema child_schema = child->getOutputSchema();
            QuerySchema out_schema;
            int out_ord = 0;

            for (int32_t ord : group_by_ordinals_) {
                try {
                    QueryFieldDesc f = child_schema.getField(ord);
                    f.setOrdinal(out_ord++);
                    out_schema.putField(f);
                } catch (...) {
                    QueryFieldDesc f(out_ord++, "group_" + std::to_string(ord), "fhe_agg", FieldType::LONG, 0);
                    out_schema.putField(f);
                }
            }

            for (const auto& agg : aggregate_definitions_) {
                FieldType out_type = FieldType::LONG;
                if (agg.type == AggregateId::SUM && agg.ordinal >= 0) {
                    try {
                        out_type = child_schema.getField(agg.ordinal).getType();
                        if (out_type == FieldType::INT || out_type == FieldType::DATE || out_type == FieldType::BOOL) {
                            out_type = FieldType::LONG;
                        }
                    } catch (...) {
                        out_type = FieldType::LONG;
                    }
                }
                QueryFieldDesc fd(out_ord++, agg.alias, "fhe_agg", out_type, 0);
                out_schema.putField(fd);
            }

            try {
                QueryFieldDesc dummy = child_schema.getField(-1);
                out_schema.putField(dummy);
            } catch (...) {
                // no-op
            }
            out_schema.initializeFieldOffsets();
            output_schema_ = out_schema;
        }

        std::shared_ptr<ColumnTableBase<void>> FheAggregate::runSelf() {
            if (!input_) {
                ColumnOperator<void>* child_op = getChild(0);
                if (!child_op) {
                    throw std::runtime_error("FheAggregate: child operator is null");
                }

                auto child_result = child_op->runSelf();
                input_ = std::dynamic_pointer_cast<FheColumnTable>(child_result);
                if (!input_) {
                    throw std::runtime_error("FheAggregate: child operator must return FheColumnTable");
                }
            }

            // Start timing only for this operator's own work (exclude child runtime)
            startTiming();

            // Bin metadata must exist (created during scan with group-by information)
            if (!input_->hasBinMetadata()) {
                throw std::runtime_error("FheAggregate: bin metadata is required. Please ensure scan operator creates bin metadata with group-by information.");
            }

            // Get group-by ordinals from bin metadata (set by scan operator)
            this->group_by_ordinals_ = input_->getBinGroupByOrdinals();

            ScopedPerfCacheMissCounter perf_agg("FheAggregate");
            perf_agg.start();
            auto result = runSelfWithBinMetadata();
            perf_agg.stopAndPrint();
            endTiming();
            printTiming();
            return result;
        }


        // Efficient aggregation using bin metadata and dummy_tag (indicator)
        std::shared_ptr<ColumnTableBase<void>> FheAggregate::runSelfWithBinMetadata() {
            // Disable OpenFHE internal parallelism to avoid nested parallelism with our group-level parallelization
            // OpenFHE uses OpenMP internally, so we set max active levels to 1 to prevent nested parallel regions
            omp_set_max_active_levels(1);

            const auto& bin_metadata = input_->getBinMetadata();
            size_t num_groups = bin_metadata.size();
            if (num_groups == 0) {
                auto output_schema = QuerySchema();
                auto empty_output = std::make_shared<FheColumnTable>(output_schema, 0);
                this->output_ = empty_output;
                return this->output_;
            }

            // ── QueryPlan/Agg: compute and apply optimal thread count (v3) ──
            int optimal_T_agg = omp_get_max_threads();  // fallback
            {
                const auto& plan = vaultdb::getCurrentQueryPlan();
                const vaultdb::ServerProfile& sp = vaultdb::globalServerProfile();

                if (sp.is_loaded) {
                    FheManager& cm_fhe_manager = FheManager::getInstance();
                    size_t rns_channels = cm_fhe_manager.getRnsCount();
                    if (rns_channels == 0) rns_channels = 1;
                    size_t agg_work_items = num_groups * rns_channels;

                    optimal_T_agg = sp.logical_cores;  // rotation-bound: always use H
                    double rho = (sp.l3_cache_bytes > 0)
                        ? static_cast<double>(plan.working_set_agg_bytes)
                          / static_cast<double>(sp.l3_cache_bytes) : 2.0;
                    std::cout << std::fixed << std::setprecision(2);
                    std::cout << "[QueryPlan/Agg] SMT: rho=" << rho
                              << " -> T*=" << optimal_T_agg
                              << " (rotation-bound: always H)" << std::endl;
                    // --fhe_force_threads override
                    if (FLAGS_fhe_force_threads > 0) {
                        std::cout << "[QueryPlan/Agg] OVERRIDE: T*=" << optimal_T_agg
                                  << " -> T=" << FLAGS_fhe_force_threads
                                  << " (--fhe_force_threads)" << std::endl;
                        optimal_T_agg = FLAGS_fhe_force_threads;
                    }
                } else {
                    std::cout << "[QueryPlan/Agg] no profile loaded"
                              << " — using OMP_NUM_THREADS="
                              << omp_get_max_threads() << std::endl;
                }
            }

            vaultdb::ScopedOmpThreads scoped_agg_threads(optimal_T_agg);
            // ── End QueryPlan/Agg ──

            auto plain_snapshot = input_->getPlainSnapshot();
            if (!plain_snapshot) {
                throw std::runtime_error("FheAggregate: input table lacks plain snapshot");
            }

            auto dummy_tag_col = input_->getDummyTagColumn();
            if (!dummy_tag_col) {
                throw std::runtime_error("FheAggregate: input table must have dummy_tag column (getDummyTagColumn)");
            }

            // FHE convention: 1=valid, 0=dummy. COUNT = sum(dummy_tag), SUM = sum(value * dummy_tag).
            auto working_aggregates = aggregate_definitions_;

            // 2. Build Output Schema & Plain Output Table (for Group Keys + aggregates + dummy_tag)
            QuerySchema output_schema;
            int output_ordinal = 0;
            for (int32_t ord : group_by_ordinals_) {
                auto field_desc = plain_snapshot->getSchema().getField(ord);
                QueryFieldDesc output_field(output_ordinal++, field_desc.getName(), field_desc.getTableName(), field_desc.getType(), field_desc.getStringLength());
                output_schema.putField(output_field);
            }
            for (const auto& agg_def : working_aggregates) {
                FieldType output_type;
                if (agg_def.type == AggregateId::COUNT) {
                    output_type = FieldType::LONG;
                } else if (agg_def.type == AggregateId::SUM) {
                    output_type = plain_snapshot->getSchema().getField(agg_def.ordinal).getType();
                }
                QueryFieldDesc output_field(output_ordinal++, agg_def.alias, "", output_type);
                output_schema.putField(output_field);
            }
            const int kDummyTagOrdinal = -1;
            output_schema.putField(QueryFieldDesc(kDummyTagOrdinal, "dummy_tag", "", FieldType::BOOL));
            output_schema.initializeFieldOffsets();

            // Create plain output for Group Keys
            auto plain_output = std::make_shared<PlainColumnTable>(output_schema, num_groups);
            for (size_t col_idx = 0; col_idx < group_by_ordinals_.size(); ++col_idx) {
                int32_t ord = group_by_ordinals_[col_idx];
                auto field_desc = plain_snapshot->getSchema().getField(ord);
                std::string col_name = field_desc.getName();
                auto plain_output_column = std::make_shared<PlainColumn>(col_name);
                std::vector<PlainField> plain_values;
                plain_values.reserve(num_groups);
                for (size_t group_idx = 0; group_idx < num_groups; ++group_idx) {
                    plain_values.push_back(bin_metadata[group_idx].group_key_values[col_idx]);
                }
                auto plain_chunk = std::make_shared<PlainColumnChunk>(plain_values);
                plain_output_column->addChunk(plain_chunk);
                plain_output->addColumn(col_name, plain_output_column);
            }
            // Add plain dummy_tag column (1=valid group). Encrypted column added after aggregates.
            {
                auto plain_dummy_col = std::make_shared<PlainColumn>("dummy_tag");
                std::vector<PlainField> dummy_vals(num_groups, PlainField(FieldType::BOOL, true));
                plain_dummy_col->addChunk(std::make_shared<PlainColumnChunk>(dummy_vals));
                plain_output->addColumn("dummy_tag", plain_dummy_col);
            }

            auto output = std::make_shared<FheColumnTable>(plain_output, std::unordered_set<std::string>{});

            // 3. Setup FHE Contexts
            FheManager& fhe_manager = FheManager::getInstance();
            auto cc_comp = fhe_manager.getComparisonCryptoContext();
            auto pk_comp = fhe_manager.getComparisonPublicKey();
            size_t pack_slots = fhe_manager.getBFVComparisonBatchSize();

            // Output context
            auto cc_int = fhe_manager.getIntegerCryptoContext();
            auto pk_int = fhe_manager.getIntegerPublicKey();
            size_t pack_slots_int = fhe_manager.getBFVBatchSize();
            std::vector<ChannelOpStats> op_stats(std::max<size_t>(1, fhe_manager.getRnsCount()));

            // 4. Opt 2: Sum only over first range_length slots (log2(L) rotations instead of log2(pack_slots)).
            // Early return for L <= 1
            auto sumSlotsInRangeLength = [&](CryptoContext<DCRTPoly> crypto_cc,
                                             const Ciphertext<DCRTPoly>& ct,
                                             size_t range_length,
                                             size_t stat_ch) -> Ciphertext<DCRTPoly> {
                size_t L = std::min(range_length, pack_slots);
                if (L <= 1) return ct;  // single slot or empty: nothing to sum
                Ciphertext<DCRTPoly> result = ct;
                int levels = static_cast<int>(std::ceil(std::log2(static_cast<double>(L))));
                size_t step = 1;
                for (int lv = 0; lv < levels; ++lv, step *= 2) {
                    auto rotated = crypto_cc->EvalRotate(result, static_cast<int32_t>(step));
                    op_stats[stat_ch].eval_rotate.fetch_add(1, std::memory_order_relaxed);
                    op_stats[stat_ch].eval_keyswitch.fetch_add(1, std::memory_order_relaxed);
                    result = crypto_cc->EvalAdd(result, rotated);
                    op_stats[stat_ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                }
                return result;
            };

            // 4a. Sum All Slots (full pack_slots; delegates to range-length sum).
            auto sumAllSlots = [&](CryptoContext<DCRTPoly> crypto_cc,
                                   const Ciphertext<DCRTPoly>& ct,
                                   size_t stat_ch) -> Ciphertext<DCRTPoly> {
                return sumSlotsInRangeLength(crypto_cc, ct, pack_slots, stat_ch);
            };

            // 4b. OPT-A5: Tree-based EvalAddMany with parallel pair-additions.
            auto evalAddMany = [&](CryptoContext<DCRTPoly> crypto_cc,
                                   std::vector<Ciphertext<DCRTPoly>> cts,
                                   size_t stat_ch) -> Ciphertext<DCRTPoly> {
                if (cts.empty()) throw std::runtime_error("FheAggregate: evalAddMany empty");
                while (cts.size() > 1) {
                    size_t half = cts.size() / 2;
                    std::vector<Ciphertext<DCRTPoly>> next(half);
                    #pragma omp parallel for schedule(static) if(half >= 8)
                    for (size_t i = 0; i < half; ++i) {
                        next[i] = crypto_cc->EvalAdd(cts[2*i], cts[2*i + 1]);
                        op_stats[stat_ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (cts.size() % 2 == 1) next.push_back(std::move(cts.back()));
                    cts = std::move(next);
                }
                return cts[0];
            };

            // 5. Helper Lambda: Sum Range (for partial chunks - masking required)
            auto sumSlotRange = [&](CryptoContext<DCRTPoly> crypto_cc,
                                    const Ciphertext<DCRTPoly>& ct,
                                    size_t range_start,
                                    size_t range_end,
                                    size_t stat_ch) -> Ciphertext<DCRTPoly> {
                // Mask out slots outside [range_start, range_end]
                std::vector<int64_t> mask_vec(pack_slots, 0);

                // Safety check for range
                if (range_start > range_end || range_start >= pack_slots) {
                    // Return encryption of 0 if range is invalid
                    return cachedZeroCi(crypto_cc, pk_comp, pack_slots);
                }

                for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) {
                    mask_vec[i] = 1;
                }
                Plaintext mask_pt = crypto_cc->MakePackedPlaintext(mask_vec);
                // EvalMult increases depth!
                auto masked = crypto_cc->EvalMult(ct, mask_pt);
                op_stats[stat_ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);

                // Opt 2: range-length sum (log2(L) rotations)
                size_t range_length = range_end - range_start + 1;
                return sumSlotsInRangeLength(crypto_cc, masked, range_length, stat_ch);
            };

            // 5b. Prefix-Sum Helper Lambdas
            // Compute inclusive prefix sum: prefix[i] = sum(ct[0..i])
            // Cost: ceil(log2(effective_len)) rotations + ct-pt mults.
            auto computePrefixSum = [&](CryptoContext<DCRTPoly> crypto_cc,
                                        const Ciphertext<DCRTPoly>& ct,
                                        size_t effective_len,
                                        size_t stat_ch) -> Ciphertext<DCRTPoly> {
                if (effective_len <= 1) return ct;
                Ciphertext<DCRTPoly> prefix = ct;
                for (size_t d = 0; (1ULL << d) < effective_len; ++d) {
                    int32_t offset = static_cast<int32_t>(1ULL << d);
                    // Rotate RIGHT by offset: slot[i] gets value from slot[i - offset]
                    auto shifted = crypto_cc->EvalRotate(prefix, -offset);
                    op_stats[stat_ch].eval_rotate.fetch_add(1, std::memory_order_relaxed);
                    op_stats[stat_ch].eval_keyswitch.fetch_add(1, std::memory_order_relaxed);
                    // Mask out wrapped slots [0, offset-1]
                    std::vector<int64_t> mask(pack_slots, 0);
                    for (size_t i = static_cast<size_t>(offset); i < pack_slots; ++i) {
                        mask[i] = 1;
                    }
                    Plaintext mask_pt = crypto_cc->MakePackedPlaintext(mask);
                    shifted = crypto_cc->EvalMult(shifted, mask_pt);
                    op_stats[stat_ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                    prefix = crypto_cc->EvalAdd(prefix, shifted);
                    op_stats[stat_ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                }
                return prefix;
            };

            // Extract slot[src_slot] from ciphertext and place at target_slot.
            // Uses mask + sumAllSlots (broadcast) + target mask to avoid arbitrary
            // rotation indices — only power-of-2 keys are available.
            // Cost: 2 ct-pt mults + log2(pack_slots) rotations.
            auto extractSlotToTarget = [&](CryptoContext<DCRTPoly> crypto_cc,
                                            const Ciphertext<DCRTPoly>& prefix,
                                            size_t src_slot,
                                            size_t target_slot,
                                            size_t stat_ch) -> Ciphertext<DCRTPoly> {
                std::vector<int64_t> mask(pack_slots, 0);
                mask[src_slot] = 1;
                Plaintext mask_pt = crypto_cc->MakePackedPlaintext(mask);
                auto masked = crypto_cc->EvalMult(prefix, mask_pt);
                op_stats[stat_ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                // Broadcast the isolated slot value to ALL slots via sumAllSlots
                auto broadcast = sumAllSlots(crypto_cc, masked, stat_ch);
                // Mask to keep only the target slot
                Plaintext target_pt = cachedTargetMask(crypto_cc, target_slot, pack_slots);
                auto result = crypto_cc->EvalMult(broadcast, target_pt);
                op_stats[stat_ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                return result;
            };

            // Extract sum of slots [range_start, range_end] from pre-computed prefix sum.
            // Places result at target_slot.
            // Cost: 1-2 ct-pt mults + 1-2 rotations + 0-1 subtraction.
            auto extractGroupSumFromPrefix = [&](CryptoContext<DCRTPoly> crypto_cc,
                                                  const Ciphertext<DCRTPoly>& prefix,
                                                  size_t range_start,
                                                  size_t range_end,
                                                  size_t target_slot,
                                                  size_t stat_ch) -> Ciphertext<DCRTPoly> {
                auto end_val = extractSlotToTarget(crypto_cc, prefix, range_end, target_slot, stat_ch);
                if (range_start == 0) {
                    return end_val;
                }
                auto start_val = extractSlotToTarget(crypto_cc, prefix, range_start - 1, target_slot, stat_ch);
                auto result = crypto_cc->EvalSub(end_val, start_val);
                op_stats[stat_ch].eval_sub.fetch_add(1, std::memory_order_relaxed);
                return result;
            };

            // 6. Dummy tag column: FHE convention 1=valid, 0=dummy.
            // COUNT = sum(dummy_tag); SUM = sum(value * dummy_tag).
            if (FLAGS_debug) std::cout << "[FheAggregate][Debug] groups=" << num_groups
                      << " group_by_cols=" << group_by_ordinals_.size()
                      << " dummy_tag_col=" << dummy_tag_col->getName()
                      << std::endl;

            // ===== Batch-parallel weighted_value precomputation for ALL SUM columns =====
            // Hoist the value×dummy_tag multiplication out of the per-aggregate loop
            // so all (column, chunk, channel) triples are computed in one OMP region.
            size_t precomp_rns_level = fhe_manager.getRnsCount();
            if (precomp_rns_level == 0) precomp_rns_level = 1;

            std::vector<std::string> sum_col_names;
            std::unordered_map<std::string, size_t> sum_col_to_precomp_idx;
            std::shared_ptr<FheColumn> precomp_indicator_col = dummy_tag_col;

            if (precomp_rns_level > 1) {
                // Ensure dummy_tag encrypted at full RNS level
                input_->ensureEncrypted(dummy_tag_col->getName(), precomp_rns_level);
                precomp_indicator_col = input_->getFheColumn(dummy_tag_col->getName());
                if (!precomp_indicator_col) precomp_indicator_col = dummy_tag_col;
                if (precomp_indicator_col->getRnsLevel() > precomp_rns_level) {
                    precomp_rns_level = precomp_indicator_col->getRnsLevel();
                }
            }

            // Collect all SUM column names (no bulk encryption — per-chunk encrypt below)
            for (const auto& agg_def : working_aggregates) {
                if (agg_def.type != AggregateId::SUM) continue;
                std::string col_name = plain_snapshot->getSchema().getField(agg_def.ordinal).getName();
                if (sum_col_to_precomp_idx.count(col_name)) continue; // already collected
                sum_col_to_precomp_idx[col_name] = sum_col_names.size();
                sum_col_names.push_back(col_name);
            }

            // Pre-compute weighted_value_all[col_idx][chunk_idx][ch] in parallel
            std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>> weighted_value_all(sum_col_names.size());

            if (!sum_col_names.empty() && precomp_rns_level > 1) {
                // Compute per-column max chunk index from bin_metadata
                std::vector<size_t> col_max_chunks(sum_col_names.size(), 0);
                for (size_t col_idx = 0; col_idx < sum_col_names.size(); ++col_idx) {
                    for (size_t g = 0; g < num_groups; ++g) {
                        const auto& info = bin_metadata[g].column_bin_info.find(sum_col_names[col_idx]);
                        if (info != bin_metadata[g].column_bin_info.end())
                            col_max_chunks[col_idx] = std::max(col_max_chunks[col_idx], info->second.end_chunk_idx);
                    }
                }

                // Allocate storage
                for (size_t col_idx = 0; col_idx < sum_col_names.size(); ++col_idx) {
                    size_t num_c = col_max_chunks[col_idx] + 1;
                    weighted_value_all[col_idx].resize(num_c);
                    for (size_t c = 0; c < num_c; ++c)
                        weighted_value_all[col_idx][c].resize(precomp_rns_level);
                }

                // Build flat work-item list: one per (col, chunk) — encrypt once, use all channels
                struct PrecompWork { size_t col_idx, chunk_idx; };
                std::vector<PrecompWork> precomp_work;
                for (size_t col_idx = 0; col_idx < sum_col_names.size(); ++col_idx) {
                    size_t num_c = col_max_chunks[col_idx] + 1;
                    for (size_t chunk_idx = 0; chunk_idx < num_c; ++chunk_idx) {
                        precomp_work.push_back({col_idx, chunk_idx});
                    }
                }

                if (FLAGS_debug) std::cout << "[FheAggregate][Precomp] Parallel weighted_value: "
                          << sum_col_names.size() << " SUM cols, "
                          << precomp_work.size() << " work items (cols×chunks), "
                          << precomp_rns_level << " channels each"
                          << std::endl;

                #pragma omp parallel for schedule(dynamic)
                for (size_t w = 0; w < precomp_work.size(); ++w) {
                    size_t col_idx = precomp_work[w].col_idx;
                    size_t chunk_idx = precomp_work[w].chunk_idx;

                    // Encrypt this single chunk (all RNS channels)
                    std::shared_ptr<FheColumnChunk> enc_chunk;
                    if (FLAGS_all_column_encrypt && input_->hasEncryptedColumn(sum_col_names[col_idx])) {
                        // CT-CT path: use pre-encrypted column from FheSqlInput cache
                        auto pre_enc_col = input_->getFheColumn(sum_col_names[col_idx]);
                        if (pre_enc_col && chunk_idx < pre_enc_col->getFheChunks().size()) {
                            enc_chunk = pre_enc_col->getFheChunks()[chunk_idx];
                        }
                    }
                    if (!enc_chunk) {
                        // CT-PT path (default): encrypt on-the-fly
                        try {
                            enc_chunk = input_->encryptSingleChunk(
                                sum_col_names[col_idx], chunk_idx, precomp_rns_level);
                        } catch (...) {
                            enc_chunk = nullptr;
                        }
                    }

                    for (size_t ch = 0; ch < precomp_rns_level; ++ch) {
                        auto cc_ch = fhe_manager.getRnsContext(ch);
                        auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;

                        if (!enc_chunk ||
                            chunk_idx >= precomp_indicator_col->getFheChunks().size()) {
                            weighted_value_all[col_idx][chunk_idx][ch] = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                            continue;
                        }
                        auto ind_chunk = precomp_indicator_col->getFheChunks()[chunk_idx];
                        if (!ind_chunk) {
                            weighted_value_all[col_idx][chunk_idx][ch] = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                            continue;
                        }
                        auto v = enc_chunk->getCiphertext(ch);
                        auto d = ind_chunk->getCiphertext(ch);
                        weighted_value_all[col_idx][chunk_idx][ch] = cc_ch->EvalMultAndRelinearize(v, d);
                        op_stats[ch].eval_mult_ct_ct.fetch_add(1, std::memory_order_relaxed);
                        op_stats[ch].eval_relinearize.fetch_add(1, std::memory_order_relaxed);
                    }
                    // enc_chunk goes out of scope here → freed immediately
                }

                std::cout << "[FheAggregate][Memory] phase=precomp"
                          << " chunks=" << precomp_work.size()
                          << " cols=" << sum_col_names.size()
                          << " rns_ch=" << precomp_rns_level
                          << " peak_simultaneous_chunks=1"
                          << " weighted_ct_count=" << (precomp_work.size() * precomp_rns_level)
                          << std::endl;
            }

            // Log per-group chunk spans (for Phase 2 sliding-window analysis)
            if (!sum_col_names.empty()) {
                for (size_t group_idx = 0; group_idx < num_groups; ++group_idx) {
                    const auto& gm = bin_metadata[group_idx];
                    const auto& info = gm.column_bin_info.find(sum_col_names[0]);
                    if (info != gm.column_bin_info.end()) {
                        size_t min_c = info->second.start_chunk_idx;
                        size_t max_c = info->second.end_chunk_idx;
                        std::cout << "[FheAggregate][BinMeta]"
                                  << " group_id=" << group_idx
                                  << " chunk_range=" << min_c << ".." << max_c
                                  << " span=" << (max_c - min_c + 1)
                                  << std::endl;
                    }
                }
            }

            // 8. Process Aggregates
            // Fused RNS path: when all aggregates use RNS and group count is low,
            // process all aggregates in a single OMP region to eliminate redundant
            // fork/join cycles and parallelize accumulator allocation.
            static constexpr bool kUsePrefixSum = false;  // Disabled: requires non-power-of-2 rotation keys
            bool used_fused_rns = false;
            {
                const int fused_max_threads = omp_get_max_threads();
                if ((precomp_rns_level > 1) && (num_groups < static_cast<size_t>(fused_max_threads))) {
                    used_fused_rns = true;

                    size_t slots_per_chunk = pack_slots;
                    size_t num_packed_chunks = (num_groups + slots_per_chunk - 1) / slots_per_chunk;
                    const int num_threads = fused_max_threads;
                    size_t fused_rns = precomp_rns_level;

                    // Determine if COUNT aggregate exists
                    bool has_count = false;
                    for (const auto& ad : working_aggregates) {
                        if (ad.type == AggregateId::COUNT) { has_count = true; break; }
                    }

                    // Pre-allocate ALL accumulators (resized but not yet encrypted)
                    // COUNT: [num_threads][num_packed_chunks][fused_rns]
                    std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>> fused_acc_count;
                    if (has_count) {
                        fused_acc_count.resize(num_threads);
                        for (int t = 0; t < num_threads; ++t) {
                            fused_acc_count[t].resize(num_packed_chunks);
                            for (size_t c = 0; c < num_packed_chunks; ++c)
                                fused_acc_count[t][c].resize(fused_rns);
                        }
                    }
                    // SUM: [col_idx][num_threads][num_packed_chunks][fused_rns]
                    std::vector<std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>>> fused_acc_sum(sum_col_names.size());
                    for (size_t si = 0; si < sum_col_names.size(); ++si) {
                        fused_acc_sum[si].resize(num_threads);
                        for (int t = 0; t < num_threads; ++t) {
                            fused_acc_sum[si][t].resize(num_packed_chunks);
                            for (size_t c = 0; c < num_packed_chunks; ++c)
                                fused_acc_sum[si][t][c].resize(fused_rns);
                        }
                    }

                    // Parallel zero-encryption of all accumulators in one OMP region
                    {
                        size_t count_items = has_count ? (static_cast<size_t>(num_threads) * num_packed_chunks * fused_rns) : 0;
                        size_t per_sum_items = static_cast<size_t>(num_threads) * num_packed_chunks * fused_rns;
                        size_t total_acc_work = count_items + sum_col_names.size() * per_sum_items;
                        #pragma omp parallel for schedule(static)
                        for (size_t w = 0; w < total_acc_work; ++w) {
                            if (w < count_items) {
                                size_t ch = w % fused_rns;
                                size_t rem = w / fused_rns;
                                size_t c = rem % num_packed_chunks;
                                size_t t = rem / num_packed_chunks;
                                auto cc_ch = fhe_manager.getRnsContext(ch);
                                auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                                fused_acc_count[t][c][ch] = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                            } else {
                                size_t sw = w - count_items;
                                size_t si = sw / per_sum_items;
                                size_t sr = sw % per_sum_items;
                                size_t ch = sr % fused_rns;
                                size_t rem = sr / fused_rns;
                                size_t c = rem % num_packed_chunks;
                                size_t t = rem / num_packed_chunks;
                                auto cc_ch = fhe_manager.getRnsContext(ch);
                                auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                                fused_acc_sum[si][t][c][ch] = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                            }
                        }
                    }

                    // ======= Prefix-Sum Cache =======
                    // COUNT prefix cache: prefix_count_cache[chunk_idx][ch]
                    std::vector<std::vector<Ciphertext<DCRTPoly>>> prefix_count_cache;
                    // SUM prefix cache: prefix_sum_cache[col_idx][chunk_idx][ch]
                    std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>> prefix_sum_cache;

                    if (kUsePrefixSum) {
                        // Determine max chunk needed for COUNT
                        size_t max_count_chunk = 0;
                        for (size_t g = 0; g < num_groups; ++g) {
                            size_t end_row = bin_metadata[g].original_end_row;
                            if (end_row > 0) {
                                size_t end_chunk = (end_row - 1) / pack_slots;
                                max_count_chunk = std::max(max_count_chunk, end_chunk);
                            }
                        }
                        size_t num_count_chunks = max_count_chunk + 1;
                        prefix_count_cache.resize(num_count_chunks);
                        for (auto& v : prefix_count_cache) v.resize(fused_rns);

                        prefix_sum_cache.resize(sum_col_names.size());
                        for (size_t si = 0; si < sum_col_names.size(); ++si) {
                            size_t num_c = weighted_value_all[si].size();
                            prefix_sum_cache[si].resize(num_c);
                            for (auto& v : prefix_sum_cache[si]) v.resize(fused_rns);
                        }

                        // Build work items for parallel prefix computation
                        struct PrefixWork {
                            enum Type { COUNT_PREFIX, SUM_PREFIX } type;
                            size_t chunk_idx, ch, col_idx;
                        };
                        std::vector<PrefixWork> prefix_work;
                        for (size_t chunk_idx = 0; chunk_idx < num_count_chunks; ++chunk_idx) {
                            for (size_t ch = 0; ch < fused_rns; ++ch) {
                                prefix_work.push_back({PrefixWork::COUNT_PREFIX, chunk_idx, ch, 0});
                            }
                        }
                        for (size_t si = 0; si < sum_col_names.size(); ++si) {
                            for (size_t chunk_idx = 0; chunk_idx < weighted_value_all[si].size(); ++chunk_idx) {
                                for (size_t ch = 0; ch < fused_rns; ++ch) {
                                    prefix_work.push_back({PrefixWork::SUM_PREFIX, chunk_idx, ch, si});
                                }
                            }
                        }

                        if (FLAGS_debug) std::cout << "[FheAggregate][PrefixSum] Computing " << prefix_work.size()
                                  << " prefix sums (COUNT chunks=" << num_count_chunks
                                  << " SUM cols=" << sum_col_names.size() << ")" << std::endl;

                        #pragma omp parallel for schedule(dynamic)
                        for (size_t w = 0; w < prefix_work.size(); ++w) {
                            auto& pw = prefix_work[w];
                            auto cc_ch = fhe_manager.getRnsContext(pw.ch);
                            if (pw.type == PrefixWork::COUNT_PREFIX) {
                                if (pw.chunk_idx < precomp_indicator_col->getFheChunks().size()) {
                                    auto ind_chunk = precomp_indicator_col->getFheChunks()[pw.chunk_idx];
                                    if (ind_chunk) {
                                        auto ct = ind_chunk->getCiphertext(pw.ch);
                                        size_t eff_len = ind_chunk->packed_count;
                                        prefix_count_cache[pw.chunk_idx][pw.ch] =
                                            computePrefixSum(cc_ch, ct, eff_len, pw.ch);
                                    }
                                }
                            } else {
                                if (pw.chunk_idx < weighted_value_all[pw.col_idx].size() &&
                                    pw.ch < weighted_value_all[pw.col_idx][pw.chunk_idx].size()) {
                                    auto& wv = weighted_value_all[pw.col_idx][pw.chunk_idx][pw.ch];
                                    size_t eff_len = pack_slots;
                                    prefix_sum_cache[pw.col_idx][pw.chunk_idx][pw.ch] =
                                        computePrefixSum(cc_ch, wv, eff_len, pw.ch);
                                }
                            }
                        }
                    }

                    // Parameterized lambda: COUNT per (group, channel)
                    auto processCountFused = [&](size_t group_idx, size_t ch) {
                        if (group_idx >= bin_metadata.size()) return;
                        const auto& group_meta = bin_metadata[group_idx];
                        size_t start_row = group_meta.original_start_row;
                        size_t end_row_excl = group_meta.original_end_row;
                        std::shared_ptr<FheColumn> ind_col = precomp_indicator_col ? precomp_indicator_col : dummy_tag_col;
                        size_t start_chunk = start_row / pack_slots;
                        size_t end_chunk = (end_row_excl > 0) ? ((end_row_excl - 1) / pack_slots) : 0;
                        auto cc_ch = fhe_manager.getRnsContext(ch);
                        auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                        size_t chunk_idx_out = group_idx / slots_per_chunk;
                        size_t target_slot = group_idx % slots_per_chunk;
                        std::vector<Ciphertext<DCRTPoly>> count_chunks;
                        size_t max_range_end = 0;
                        for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk && chunk_idx < ind_col->getFheChunks().size(); ++chunk_idx) {
                            auto dummy_chunk = ind_col->getFheChunks()[chunk_idx];
                            if (!dummy_chunk) continue;
                            size_t chunk_start_row = chunk_idx * pack_slots;
                            size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                            size_t range_end = (end_row_excl < chunk_start_row + dummy_chunk->packed_count) ? (end_row_excl - 1 - chunk_start_row) : (dummy_chunk->packed_count - 1);
                            max_range_end = std::max(max_range_end, range_end);
                            bool is_full_chunk = (range_start == 0 && range_end == pack_slots - 1);
                            auto chunk_ct = dummy_chunk->getCiphertext(ch);
                            if (!is_full_chunk) {
                                std::vector<int64_t> range_mask_vec(pack_slots, 0);
                                for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) range_mask_vec[i] = 1;
                                Plaintext range_mask_pt = cc_ch->MakePackedPlaintext(range_mask_vec);
                                chunk_ct = cc_ch->EvalMult(chunk_ct, range_mask_pt);
                                op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                            }
                            count_chunks.push_back(std::move(chunk_ct));
                        }
                        Ciphertext<DCRTPoly> count_ct;
                        if (!count_chunks.empty()) {
                            count_ct = (count_chunks.size() == 1) ? std::move(count_chunks[0]) : evalAddMany(cc_ch, std::move(count_chunks), ch);
                            // Opt: sum only [target_slot, max_range_end] instead of all pack_slots
                            size_t effective_len = std::min(max_range_end - target_slot + 1, pack_slots);
                            count_ct = sumSlotsInRangeLength(cc_ch, count_ct, effective_len, ch);
                        } else {
                            count_ct = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                        }
                        int tid = omp_get_thread_num();
                        Plaintext mask_pt_ch = cachedTargetMask(cc_ch, target_slot, pack_slots);
                        auto aligned_sum = cc_ch->EvalMult(count_ct, mask_pt_ch);
                        op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                        fused_acc_count[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(fused_acc_count[tid][chunk_idx_out][ch], aligned_sum);
                        op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                    };

                    // Parameterized lambda: SUM per (group, channel, column)
                    auto processSumFused = [&](size_t group_idx, size_t ch,
                        const std::string& col_name,
                        const std::vector<std::vector<Ciphertext<DCRTPoly>>>& wv_chunk,
                        std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>>& acc_ref) {
                        if (group_idx >= bin_metadata.size()) return;
                        const auto& group_meta = bin_metadata[group_idx];
                        const auto& col_bin_info = group_meta.column_bin_info.find(col_name);
                        if (col_bin_info == group_meta.column_bin_info.end()) {
                            throw std::runtime_error("FheAggregate: bin info not found for column: " + col_name);
                        }
                        if (FLAGS_debug && group_idx == 0 && ch == 0) {
                            std::cout << "[FheAggregate][Debug] SUM column=" << col_name
                                      << " start_chunk=" << col_bin_info->second.start_chunk_idx
                                      << " end_chunk=" << col_bin_info->second.end_chunk_idx
                                      << " slot_ranges=" << col_bin_info->second.chunk_slot_ranges.size()
                                      << " indicator_rns_level="
                                      << (precomp_indicator_col ? precomp_indicator_col->getRnsLevel() : 0)
                                      << std::endl;
                        }
                        auto cc_ch = fhe_manager.getRnsContext(ch);
                        auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                        size_t chunk_idx_out = group_idx / slots_per_chunk;
                        size_t target_slot = group_idx % slots_per_chunk;
                        std::vector<Ciphertext<DCRTPoly>> chunks_to_combine;
                        size_t max_range_end = 0;
                        for (size_t chunk_idx = col_bin_info->second.start_chunk_idx;
                             chunk_idx <= col_bin_info->second.end_chunk_idx;
                             ++chunk_idx) {
                            const auto& chunk_range_it = col_bin_info->second.chunk_slot_ranges.find(chunk_idx);
                            if (chunk_range_it == col_bin_info->second.chunk_slot_ranges.end()) continue;
                            size_t range_start = chunk_range_it->second.first;
                            size_t range_end = chunk_range_it->second.second;
                            max_range_end = std::max(max_range_end, range_end);
                            if (chunk_idx >= wv_chunk.size() || ch >= wv_chunk[chunk_idx].size()) continue;
                            Ciphertext<DCRTPoly> chunk_ct = wv_chunk[chunk_idx][ch];
                            bool is_full_chunk = (range_start == 0 && range_end == pack_slots - 1);
                            if (!is_full_chunk) {
                                std::vector<int64_t> range_mask_vec(pack_slots, 0);
                                for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) range_mask_vec[i] = 1;
                                Plaintext range_mask_pt = cc_ch->MakePackedPlaintext(range_mask_vec);
                                chunk_ct = cc_ch->EvalMult(chunk_ct, range_mask_pt);
                                op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                            }
                            chunks_to_combine.push_back(std::move(chunk_ct));
                        }
                        Ciphertext<DCRTPoly> total_sum_ch;
                        if (!chunks_to_combine.empty()) {
                            total_sum_ch = (chunks_to_combine.size() == 1)
                                ? std::move(chunks_to_combine[0])
                                : evalAddMany(cc_ch, std::move(chunks_to_combine), ch);
                            // Opt: sum only [target_slot, max_range_end] instead of all pack_slots
                            size_t effective_len = std::min(max_range_end - target_slot + 1, pack_slots);
                            total_sum_ch = sumSlotsInRangeLength(cc_ch, total_sum_ch, effective_len, ch);
                        } else {
                            total_sum_ch = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                        }
                        int tid = omp_get_thread_num();
                        Plaintext mask_pt_ch = cachedTargetMask(cc_ch, target_slot, pack_slots);
                        auto aligned_sum = cc_ch->EvalMult(total_sum_ch, mask_pt_ch);
                        op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                        acc_ref[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(acc_ref[tid][chunk_idx_out][ch], aligned_sum);
                        op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                    };

                    // Prefix-sum COUNT: extract group sums from pre-computed prefix cache
                    auto processCountFusedPrefixSum = [&](size_t group_idx, size_t ch) {
                        if (group_idx >= bin_metadata.size()) return;
                        const auto& group_meta = bin_metadata[group_idx];
                        size_t start_row = group_meta.original_start_row;
                        size_t end_row_excl = group_meta.original_end_row;
                        size_t start_chunk = start_row / pack_slots;
                        size_t end_chunk = (end_row_excl > 0) ? ((end_row_excl - 1) / pack_slots) : 0;
                        auto cc_ch = fhe_manager.getRnsContext(ch);
                        auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                        size_t chunk_idx_out = group_idx / slots_per_chunk;
                        size_t target_slot = group_idx % slots_per_chunk;
                        std::vector<Ciphertext<DCRTPoly>> partial_counts;
                        for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk; ++chunk_idx) {
                            if (chunk_idx >= prefix_count_cache.size() ||
                                ch >= prefix_count_cache[chunk_idx].size() ||
                                !prefix_count_cache[chunk_idx][ch]) continue;
                            auto& prefix = prefix_count_cache[chunk_idx][ch];
                            size_t chunk_start_row = chunk_idx * pack_slots;
                            std::shared_ptr<FheColumn> ind_col = precomp_indicator_col ? precomp_indicator_col : dummy_tag_col;
                            auto ind_chunk = ind_col->getFheChunks()[chunk_idx];
                            size_t chunk_packed = ind_chunk ? ind_chunk->packed_count : pack_slots;
                            size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                            size_t range_end = (end_row_excl < chunk_start_row + chunk_packed)
                                ? (end_row_excl - 1 - chunk_start_row) : (chunk_packed - 1);
                            auto partial = extractGroupSumFromPrefix(
                                cc_ch, prefix, range_start, range_end, target_slot, ch);
                            partial_counts.push_back(std::move(partial));
                        }
                        Ciphertext<DCRTPoly> count_at_target;
                        if (!partial_counts.empty()) {
                            count_at_target = (partial_counts.size() == 1)
                                ? std::move(partial_counts[0])
                                : evalAddMany(cc_ch, std::move(partial_counts), ch);
                        } else {
                            count_at_target = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                        }
                        int tid = omp_get_thread_num();
                        fused_acc_count[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(
                            fused_acc_count[tid][chunk_idx_out][ch], count_at_target);
                        op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                    };

                    // Prefix-sum SUM: extract group sums from pre-computed prefix cache
                    auto processSumFusedPrefixSum = [&](size_t group_idx, size_t ch,
                        const std::string& col_name, size_t col_idx,
                        std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>>& acc_ref) {
                        if (group_idx >= bin_metadata.size()) return;
                        const auto& group_meta = bin_metadata[group_idx];
                        const auto& col_bin_info = group_meta.column_bin_info.find(col_name);
                        if (col_bin_info == group_meta.column_bin_info.end()) return;
                        auto cc_ch = fhe_manager.getRnsContext(ch);
                        auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                        size_t chunk_idx_out = group_idx / slots_per_chunk;
                        size_t target_slot = group_idx % slots_per_chunk;
                        std::vector<Ciphertext<DCRTPoly>> partial_sums;
                        for (size_t chunk_idx = col_bin_info->second.start_chunk_idx;
                             chunk_idx <= col_bin_info->second.end_chunk_idx;
                             ++chunk_idx) {
                            const auto& chunk_range_it = col_bin_info->second.chunk_slot_ranges.find(chunk_idx);
                            if (chunk_range_it == col_bin_info->second.chunk_slot_ranges.end()) continue;
                            if (col_idx >= prefix_sum_cache.size() ||
                                chunk_idx >= prefix_sum_cache[col_idx].size() ||
                                ch >= prefix_sum_cache[col_idx][chunk_idx].size() ||
                                !prefix_sum_cache[col_idx][chunk_idx][ch]) continue;
                            auto& prefix = prefix_sum_cache[col_idx][chunk_idx][ch];
                            size_t range_start = chunk_range_it->second.first;
                            size_t range_end = chunk_range_it->second.second;
                            auto partial = extractGroupSumFromPrefix(
                                cc_ch, prefix, range_start, range_end, target_slot, ch);
                            partial_sums.push_back(std::move(partial));
                        }
                        Ciphertext<DCRTPoly> sum_at_target;
                        if (!partial_sums.empty()) {
                            sum_at_target = (partial_sums.size() == 1)
                                ? std::move(partial_sums[0])
                                : evalAddMany(cc_ch, std::move(partial_sums), ch);
                        } else {
                            sum_at_target = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                        }
                        int tid = omp_get_thread_num();
                        acc_ref[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(
                            acc_ref[tid][chunk_idx_out][ch], sum_at_target);
                        op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                    };

                    // Single fused OMP region for all (group, channel) work
                    const size_t fused_total_work = num_groups * fused_rns;
                    #pragma omp parallel for schedule(static)
                    for (size_t work_idx = 0; work_idx < fused_total_work; ++work_idx) {
                        size_t group_idx = work_idx / fused_rns;
                        size_t ch = work_idx % fused_rns;
                        if (has_count) {
                            if (kUsePrefixSum)
                                processCountFusedPrefixSum(group_idx, ch);
                            else
                                processCountFused(group_idx, ch);
                        }
                        for (size_t si = 0; si < sum_col_names.size(); ++si) {
                            if (kUsePrefixSum)
                                processSumFusedPrefixSum(group_idx, ch, sum_col_names[si], si, fused_acc_sum[si]);
                            else
                                processSumFused(group_idx, ch, sum_col_names[si],
                                                weighted_value_all[si], fused_acc_sum[si]);
                        }
                    }

                    // Post-processing: merge per-thread accumulators and create output columns
                    for (const auto& agg_def : working_aggregates) {
                        auto result_col = std::make_shared<FheColumn>(agg_def.alias);
                        if (agg_def.type == AggregateId::COUNT) {
                            for (size_t chunk_idx = 0; chunk_idx < num_packed_chunks; ++chunk_idx) {
                                size_t start_group = chunk_idx * slots_per_chunk;
                                size_t end_group = std::min(start_group + slots_per_chunk, num_groups);
                                size_t groups_in_chunk = end_group - start_group;
                                if (groups_in_chunk == 0 || start_group >= num_groups) continue;
                                std::vector<Ciphertext<DCRTPoly>> packed_per_channel(fused_rns);
                                for (size_t ch = 0; ch < fused_rns; ++ch) {
                                    auto cc_ch = fhe_manager.getRnsContext(ch);
                                    std::vector<Ciphertext<DCRTPoly>> to_merge;
                                    to_merge.reserve(num_threads);
                                    for (int t = 0; t < num_threads; ++t)
                                        to_merge.push_back(fused_acc_count[t][chunk_idx][ch]);
                                    packed_per_channel[ch] = (to_merge.size() == 1)
                                        ? std::move(to_merge[0])
                                        : evalAddMany(cc_ch, std::move(to_merge), ch);
                                }
                                QuantizationParams qp;
                                qp.simdSlots = slots_per_chunk;
                                FheTypeDescriptor td(FheDataType::LONG, FheEncodingType::BFV_PACKED_ENCODING);
                                result_col->addFheChunk(std::make_shared<FheColumnChunk>(packed_per_channel, qp, td, groups_in_chunk));
                            }
                        } else if (agg_def.type == AggregateId::SUM) {
                            std::string col_name = plain_snapshot->getSchema().getField(agg_def.ordinal).getName();
                            auto it = sum_col_to_precomp_idx.find(col_name);
                            if (it == sum_col_to_precomp_idx.end()) {
                                throw std::runtime_error("FheAggregate: fused SUM column index not found: " + col_name);
                            }
                            size_t si = it->second;
                            for (size_t chunk_idx = 0; chunk_idx < num_packed_chunks; ++chunk_idx) {
                                size_t start_group = chunk_idx * slots_per_chunk;
                                size_t end_group = std::min(start_group + slots_per_chunk, num_groups);
                                size_t groups_in_chunk = end_group - start_group;
                                if (groups_in_chunk == 0 || start_group >= num_groups) continue;
                                std::vector<Ciphertext<DCRTPoly>> packed_per_channel(fused_rns);
                                for (size_t ch = 0; ch < fused_rns; ++ch) {
                                    auto cc_ch = fhe_manager.getRnsContext(ch);
                                    std::vector<Ciphertext<DCRTPoly>> to_merge;
                                    to_merge.reserve(num_threads);
                                    for (int t = 0; t < num_threads; ++t)
                                        to_merge.push_back(fused_acc_sum[si][t][chunk_idx][ch]);
                                    packed_per_channel[ch] = (to_merge.size() == 1)
                                        ? std::move(to_merge[0])
                                        : evalAddMany(cc_ch, std::move(to_merge), ch);
                                }
                                QuantizationParams qp;
                                qp.simdSlots = slots_per_chunk;
                                FheTypeDescriptor td(FheDataType::LONG, FheEncodingType::BFV_PACKED_ENCODING);
                                result_col->addFheChunk(std::make_shared<FheColumnChunk>(packed_per_channel, qp, td, groups_in_chunk));
                            }
                        }
                        output->addColumn(result_col);
                    }
                }
            }

            // 8b. Fallback per-aggregate loop (non-RNS or high group count)
            if (!used_fused_rns) for (const auto& agg_def : working_aggregates) {
                std::vector<Ciphertext<DCRTPoly>> agg_values_encrypted;
                agg_values_encrypted.reserve(num_groups);

                std::string agg_col_name;
                size_t rns_level = 1;
                std::shared_ptr<FheColumn> indicator_col_for_agg = dummy_tag_col;

                if (agg_def.type == AggregateId::SUM) {
                    agg_col_name = plain_snapshot->getSchema().getField(agg_def.ordinal).getName();
                    // SUM always uses full RNS (getRnsCount() channels): l_extendedprice etc. can't predict max*cardinality.
                    rns_level = fhe_manager.getRnsCount();
                    if (rns_level == 0) rns_level = 1;
                    // No bulk encryption — per-chunk encrypt via encryptSingleChunk in weighted_value computation
                    if (rns_level > 1) {
                        std::string ind_name = dummy_tag_col->getName();
                        input_->ensureEncrypted(ind_name, rns_level);
                        indicator_col_for_agg = input_->getFheColumn(ind_name);
                        if (indicator_col_for_agg && indicator_col_for_agg->getRnsLevel() > rns_level) {
                            rns_level = indicator_col_for_agg->getRnsLevel();
                        }
                    }
                } else {
                    // COUNT aggregation: get column name from bin_metadata
                    if (!bin_metadata.empty()) {
                        const auto& first_group = bin_metadata[0];
                        if (!first_group.column_bin_info.empty()) {
                            agg_col_name = first_group.column_bin_info.begin()->first;
                        } else {
                            throw std::runtime_error("FheAggregate: column_bin_info is empty for COUNT aggregation");
                        }
                    } else {
                        throw std::runtime_error("FheAggregate: bin_metadata is empty for COUNT aggregation");
                    }
                    // Use full RNS (same as filter/SUM) when getRnsCount() > 1; else single channel
                    rns_level = fhe_manager.getRnsCount();
                    if (rns_level == 0) rns_level = 1;
                    if (rns_level > 1) {
                        std::string ind_name = dummy_tag_col->getName();
                        input_->ensureEncrypted(ind_name, rns_level);
                        indicator_col_for_agg = input_->getFheColumn(ind_name);
                        if (indicator_col_for_agg && indicator_col_for_agg->getRnsLevel() > rns_level) {
                            rns_level = indicator_col_for_agg->getRnsLevel();
                        }
                    }
                }

                bool sum_uses_rns = (agg_def.type == AggregateId::SUM && rns_level > 1);
                bool count_uses_rns = (agg_def.type == AggregateId::COUNT && rns_level > 1);
                std::vector<Ciphertext<DCRTPoly>> ones_cipher_rns;
                if (sum_uses_rns) {
                    ones_cipher_rns.resize(rns_level);
                    for (size_t ch = 0; ch < rns_level; ++ch) {
                        auto cc_ch = fhe_manager.getRnsContext(ch);
                        auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                        Plaintext ones_pt = cachedAggUniformPt(cc_ch, 1, pack_slots);
                        ones_cipher_rns[ch] = cc_ch->Encrypt(pk_ch, ones_pt);
                    }
                }

                // Opt 4: output chunk/channel (and per-thread) accumulators instead of group_results arrays
                size_t slots_per_chunk = pack_slots;
                size_t num_packed_chunks = (num_groups + slots_per_chunk - 1) / slots_per_chunk;
                const int num_threads = omp_get_max_threads();

                std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>> acc_sum(num_threads);
                std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>> acc_count(num_threads);
                std::vector<std::vector<Ciphertext<DCRTPoly>>> acc_single(num_threads);
                if (sum_uses_rns) {
                    for (int t = 0; t < num_threads; ++t) {
                        acc_sum[t].resize(num_packed_chunks);
                        for (size_t c = 0; c < num_packed_chunks; ++c) {
                            acc_sum[t][c].resize(rns_level);
                            for (size_t ch = 0; ch < rns_level; ++ch) {
                                auto cc_ch = fhe_manager.getRnsContext(ch);
                                auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                                acc_sum[t][c][ch] = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                            }
                        }
                    }
                }
                if (count_uses_rns) {
                    for (int t = 0; t < num_threads; ++t) {
                        acc_count[t].resize(num_packed_chunks);
                        for (size_t c = 0; c < num_packed_chunks; ++c) {
                            acc_count[t][c].resize(rns_level);
                            for (size_t ch = 0; ch < rns_level; ++ch) {
                                auto cc_ch = fhe_manager.getRnsContext(ch);
                                auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                                acc_count[t][c][ch] = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                            }
                        }
                    }
                }
                if (!sum_uses_rns && !count_uses_rns) {
                    for (int t = 0; t < num_threads; ++t) {
                        acc_single[t].resize(num_packed_chunks);
                        for (size_t c = 0; c < num_packed_chunks; ++c)
                            acc_single[t][c] = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                    }
                }
                // Opt 1: Use batch-precomputed weighted values for RNS SUM
                // (precomputation done in parallel above the per-aggregate loop)
                std::vector<std::vector<Ciphertext<DCRTPoly>>> weighted_value_chunk;
                if (sum_uses_rns) {
                    auto precomp_it = sum_col_to_precomp_idx.find(agg_col_name);
                    if (precomp_it != sum_col_to_precomp_idx.end()) {
                        weighted_value_chunk = std::move(weighted_value_all[precomp_it->second]);
                    } else {
                        throw std::runtime_error("FheAggregate: precomputed weighted values not found for: " + agg_col_name);
                    }
                }

                // ======= Fallback Prefix-Sum Cache =======
                std::vector<std::vector<Ciphertext<DCRTPoly>>> fb_prefix_count_cache;
                std::vector<std::vector<Ciphertext<DCRTPoly>>> fb_prefix_sum_cache;

                if (kUsePrefixSum && (count_uses_rns || sum_uses_rns)) {
                    std::shared_ptr<FheColumn> ind_col = indicator_col_for_agg ? indicator_col_for_agg : dummy_tag_col;
                    if (count_uses_rns) {
                        size_t max_chunk = 0;
                        for (size_t g = 0; g < num_groups; ++g) {
                            size_t er = bin_metadata[g].original_end_row;
                            if (er > 0) max_chunk = std::max(max_chunk, (er - 1) / pack_slots);
                        }
                        size_t nc = max_chunk + 1;
                        fb_prefix_count_cache.resize(nc);
                        for (auto& v : fb_prefix_count_cache) v.resize(rns_level);
                        #pragma omp parallel for schedule(dynamic)
                        for (size_t w = 0; w < nc * rns_level; ++w) {
                            size_t ci = w / rns_level;
                            size_t ch = w % rns_level;
                            if (ci < ind_col->getFheChunks().size()) {
                                auto chunk = ind_col->getFheChunks()[ci];
                                if (chunk) {
                                    auto cc_ch = fhe_manager.getRnsContext(ch);
                                    fb_prefix_count_cache[ci][ch] =
                                        computePrefixSum(cc_ch, chunk->getCiphertext(ch), chunk->packed_count, ch);
                                }
                            }
                        }
                    }
                    if (sum_uses_rns) {
                        size_t nc = weighted_value_chunk.size();
                        fb_prefix_sum_cache.resize(nc);
                        for (auto& v : fb_prefix_sum_cache) v.resize(rns_level);
                        #pragma omp parallel for schedule(dynamic)
                        for (size_t w = 0; w < nc * rns_level; ++w) {
                            size_t ci = w / rns_level;
                            size_t ch = w % rns_level;
                            if (ci < weighted_value_chunk.size() && ch < weighted_value_chunk[ci].size()) {
                                auto cc_ch = fhe_manager.getRnsContext(ch);
                                fb_prefix_sum_cache[ci][ch] =
                                    computePrefixSum(cc_ch, weighted_value_chunk[ci][ch], pack_slots, ch);
                            }
                        }
                    }
                }

                auto processCountRnsChannel = [&](size_t group_idx, size_t ch) {
                    if (group_idx >= bin_metadata.size()) {
                        return;
                    }
                    const auto& group_meta = bin_metadata[group_idx];
                    size_t start_row = group_meta.original_start_row;
                    size_t end_row_excl = group_meta.original_end_row;

                    std::shared_ptr<FheColumn> ind_col = indicator_col_for_agg ? indicator_col_for_agg : dummy_tag_col;
                    size_t start_chunk = start_row / pack_slots;
                    size_t end_chunk = (end_row_excl > 0) ? ((end_row_excl - 1) / pack_slots) : 0;

                    auto cc_ch = fhe_manager.getRnsContext(ch);
                    auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                    size_t chunk_idx_out = group_idx / slots_per_chunk;
                    size_t target_slot = group_idx % slots_per_chunk;

                    if (kUsePrefixSum && !fb_prefix_count_cache.empty()) {
                        std::vector<Ciphertext<DCRTPoly>> partial_counts;
                        for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk; ++chunk_idx) {
                            if (chunk_idx >= fb_prefix_count_cache.size() ||
                                ch >= fb_prefix_count_cache[chunk_idx].size() ||
                                !fb_prefix_count_cache[chunk_idx][ch]) continue;
                            auto& prefix = fb_prefix_count_cache[chunk_idx][ch];
                            size_t chunk_start_row = chunk_idx * pack_slots;
                            auto ind_chunk = ind_col->getFheChunks()[chunk_idx];
                            size_t chunk_packed = ind_chunk ? ind_chunk->packed_count : pack_slots;
                            size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                            size_t range_end = (end_row_excl < chunk_start_row + chunk_packed)
                                ? (end_row_excl - 1 - chunk_start_row) : (chunk_packed - 1);
                            partial_counts.push_back(extractGroupSumFromPrefix(
                                cc_ch, prefix, range_start, range_end, target_slot, ch));
                        }
                        Ciphertext<DCRTPoly> count_at_target;
                        if (!partial_counts.empty()) {
                            count_at_target = (partial_counts.size() == 1)
                                ? std::move(partial_counts[0])
                                : evalAddMany(cc_ch, std::move(partial_counts), ch);
                        } else {
                            count_at_target = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                        }
                        int tid = omp_get_thread_num();
                        acc_count[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(acc_count[tid][chunk_idx_out][ch], count_at_target);
                        op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                        return;
                    }

                    Ciphertext<DCRTPoly> count_ct;
                    std::vector<Ciphertext<DCRTPoly>> count_chunks;
                    size_t effective_slot_count = 0;
                    for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk && chunk_idx < ind_col->getFheChunks().size(); ++chunk_idx) {
                        auto dummy_chunk = ind_col->getFheChunks()[chunk_idx];
                        if (!dummy_chunk) continue;
                        size_t chunk_start_row = chunk_idx * pack_slots;
                        size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                        size_t range_end = (end_row_excl < chunk_start_row + dummy_chunk->packed_count) ? (end_row_excl - 1 - chunk_start_row) : (dummy_chunk->packed_count - 1);
                        effective_slot_count += (range_end - range_start + 1);
                        bool is_full_chunk = (range_start == 0 && range_end == pack_slots - 1);
                        auto chunk_ct = dummy_chunk->getCiphertext(ch);
                        if (!is_full_chunk) {
                            std::vector<int64_t> range_mask_vec(pack_slots, 0);
                            for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) range_mask_vec[i] = 1;
                            Plaintext range_mask_pt = cc_ch->MakePackedPlaintext(range_mask_vec);
                            chunk_ct = cc_ch->EvalMult(chunk_ct, range_mask_pt);
                            op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                        }
                        count_chunks.push_back(std::move(chunk_ct));
                    }
                    if (!count_chunks.empty()) {
                        Ciphertext<DCRTPoly> total_dummy_masked_ch = (count_chunks.size() == 1)
                            ? std::move(count_chunks[0])
                            : evalAddMany(cc_ch, std::move(count_chunks), ch);
                        // Opt: sum only [target_slot, max_range_end] instead of all pack_slots
                        size_t max_re = 0;
                        for (size_t ci = start_chunk; ci <= end_chunk && ci < ind_col->getFheChunks().size(); ++ci) {
                            auto dc = ind_col->getFheChunks()[ci];
                            if (!dc) continue;
                            size_t csr = ci * pack_slots;
                            size_t re = (end_row_excl < csr + dc->packed_count) ? (end_row_excl - 1 - csr) : (dc->packed_count - 1);
                            max_re = std::max(max_re, re);
                        }
                        size_t effective_len = std::min(max_re - target_slot + 1, pack_slots);
                        count_ct = sumSlotsInRangeLength(cc_ch, total_dummy_masked_ch, effective_len, ch);
                    } else {
                        count_ct = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                    }
                    int tid = omp_get_thread_num();
                    Plaintext mask_pt_ch = cachedTargetMask(cc_ch, target_slot, pack_slots);
                    auto aligned_sum = cc_ch->EvalMult(count_ct, mask_pt_ch);
                    op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                    acc_count[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(acc_count[tid][chunk_idx_out][ch], aligned_sum);
                    op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                };

                auto processSumRnsChannel = [&](size_t group_idx, size_t ch) {
                    if (group_idx >= bin_metadata.size()) {
                        return;
                    }
                    const auto& group_meta = bin_metadata[group_idx];
                    const auto& col_bin_info = group_meta.column_bin_info.find(agg_col_name);
                    if (col_bin_info == group_meta.column_bin_info.end()) {
                        throw std::runtime_error("FheAggregate: bin info not found for column: " + agg_col_name);
                    }
                    if (FLAGS_debug && group_idx == 0 && ch == 0) {
                        std::cout << "[FheAggregate][Debug] SUM column=" << agg_col_name
                                  << " start_chunk=" << col_bin_info->second.start_chunk_idx
                                  << " end_chunk=" << col_bin_info->second.end_chunk_idx
                                  << " slot_ranges=" << col_bin_info->second.chunk_slot_ranges.size()
                                  << " indicator_rns_level="
                                  << (indicator_col_for_agg ? indicator_col_for_agg->getRnsLevel() : 0)
                                  << std::endl;
                    }

                    auto cc_ch = fhe_manager.getRnsContext(ch);
                    auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                    size_t chunk_idx_out = group_idx / slots_per_chunk;
                    size_t target_slot = group_idx % slots_per_chunk;

                    if (kUsePrefixSum && !fb_prefix_sum_cache.empty()) {
                        std::vector<Ciphertext<DCRTPoly>> partial_sums;
                        for (size_t chunk_idx = col_bin_info->second.start_chunk_idx;
                             chunk_idx <= col_bin_info->second.end_chunk_idx;
                             ++chunk_idx) {
                            const auto& chunk_range_it = col_bin_info->second.chunk_slot_ranges.find(chunk_idx);
                            if (chunk_range_it == col_bin_info->second.chunk_slot_ranges.end()) continue;
                            if (chunk_idx >= fb_prefix_sum_cache.size() ||
                                ch >= fb_prefix_sum_cache[chunk_idx].size() ||
                                !fb_prefix_sum_cache[chunk_idx][ch]) continue;
                            auto& prefix = fb_prefix_sum_cache[chunk_idx][ch];
                            size_t range_start = chunk_range_it->second.first;
                            size_t range_end = chunk_range_it->second.second;
                            partial_sums.push_back(extractGroupSumFromPrefix(
                                cc_ch, prefix, range_start, range_end, target_slot, ch));
                        }
                        Ciphertext<DCRTPoly> sum_at_target;
                        if (!partial_sums.empty()) {
                            sum_at_target = (partial_sums.size() == 1)
                                ? std::move(partial_sums[0])
                                : evalAddMany(cc_ch, std::move(partial_sums), ch);
                        } else {
                            sum_at_target = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                        }
                        int tid = omp_get_thread_num();
                        acc_sum[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(acc_sum[tid][chunk_idx_out][ch], sum_at_target);
                        op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                        return;
                    }

                    std::vector<Ciphertext<DCRTPoly>> chunks_to_combine;
                    size_t effective_slot_count_sum = 0;
                    for (size_t chunk_idx = col_bin_info->second.start_chunk_idx;
                         chunk_idx <= col_bin_info->second.end_chunk_idx;
                         ++chunk_idx) {
                        const auto& chunk_range_it = col_bin_info->second.chunk_slot_ranges.find(chunk_idx);
                        if (chunk_range_it == col_bin_info->second.chunk_slot_ranges.end()) continue;
                        size_t range_start = chunk_range_it->second.first;
                        size_t range_end = chunk_range_it->second.second;
                        effective_slot_count_sum += (range_end - range_start + 1);
                        if (chunk_idx >= weighted_value_chunk.size() || ch >= weighted_value_chunk[chunk_idx].size()) continue;
                        Ciphertext<DCRTPoly> chunk_ct = weighted_value_chunk[chunk_idx][ch];
                        bool is_full_chunk = (range_start == 0 && range_end == pack_slots - 1);
                        if (!is_full_chunk) {
                            std::vector<int64_t> range_mask_vec(pack_slots, 0);
                            for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) range_mask_vec[i] = 1;
                            Plaintext range_mask_pt = cc_ch->MakePackedPlaintext(range_mask_vec);
                            chunk_ct = cc_ch->EvalMult(chunk_ct, range_mask_pt);
                            op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                        }
                        chunks_to_combine.push_back(std::move(chunk_ct));
                    }
                    Ciphertext<DCRTPoly> total_sum_ch;
                    if (!chunks_to_combine.empty()) {
                        Ciphertext<DCRTPoly> total_masked_ch = (chunks_to_combine.size() == 1)
                            ? std::move(chunks_to_combine[0])
                            : evalAddMany(cc_ch, std::move(chunks_to_combine), ch);
                        // Opt: sum only [target_slot, max_range_end] instead of all pack_slots
                        size_t max_re = 0;
                        for (auto& [ci, range] : col_bin_info->second.chunk_slot_ranges) {
                            max_re = std::max(max_re, range.second);
                        }
                        size_t effective_len = std::min(max_re - target_slot + 1, pack_slots);
                        total_sum_ch = sumSlotsInRangeLength(cc_ch, total_masked_ch, effective_len, ch);
                    } else {
                        total_sum_ch = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                    }
                    int tid = omp_get_thread_num();
                    Plaintext mask_pt_ch = cachedTargetMask(cc_ch, target_slot, pack_slots);
                    auto aligned_sum = cc_ch->EvalMult(total_sum_ch, mask_pt_ch);
                    op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                    acc_sum[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(acc_sum[tid][chunk_idx_out][ch], aligned_sum);
                    op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                };

                const int max_threads = omp_get_max_threads();
                const bool low_group_parallelism = (rns_level > 1) && (num_groups < static_cast<size_t>(max_threads));
                if (low_group_parallelism) {
                    // For low-cardinality GROUP BY (e.g., TPC-H Q1), expand work to (group, channel).
                    const size_t total_work_items = num_groups * rns_level;
                    #pragma omp parallel for schedule(static)
                    for (size_t work_idx = 0; work_idx < total_work_items; ++work_idx) {
                        size_t group_idx = work_idx / rns_level;
                        size_t ch = work_idx % rns_level;
                        if (agg_def.type == AggregateId::COUNT) {
                            processCountRnsChannel(group_idx, ch);
                        } else if (agg_def.type == AggregateId::SUM) {
                            processSumRnsChannel(group_idx, ch);
                        }
                    }
                } else {
                    // Opt 1: single-context SUM value×dummy once per chunk
                    std::vector<Ciphertext<DCRTPoly>> weighted_value_chunk_sc;
                    if (agg_def.type == AggregateId::SUM && rns_level == 1) {
                        size_t max_chunk_sc = 0;
                        for (size_t g = 0; g < num_groups; ++g) {
                            const auto& info = bin_metadata[g].column_bin_info.find(agg_col_name);
                            if (info != bin_metadata[g].column_bin_info.end())
                                max_chunk_sc = std::max(max_chunk_sc, info->second.end_chunk_idx);
                        }
                        weighted_value_chunk_sc.resize(max_chunk_sc + 1);
                        for (size_t chunk_idx = 0; chunk_idx <= max_chunk_sc; ++chunk_idx) {
                            if (chunk_idx >= dummy_tag_col->getFheChunks().size()) {
                                weighted_value_chunk_sc[chunk_idx] = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                                continue;
                            }
                            // Encrypt single chunk (single BFV context)
                            std::shared_ptr<FheColumnChunk> enc_chunk;
                            if (FLAGS_all_column_encrypt && input_->hasEncryptedColumn(agg_col_name)) {
                                auto pre_enc_col = input_->getFheColumn(agg_col_name);
                                if (pre_enc_col && chunk_idx < pre_enc_col->getFheChunks().size()) {
                                    enc_chunk = pre_enc_col->getFheChunks()[chunk_idx];
                                }
                            }
                            if (!enc_chunk) {
                                enc_chunk = input_->encryptSingleChunk(agg_col_name, chunk_idx, 1);
                            }
                            auto ind_chunk = dummy_tag_col->getFheChunks()[chunk_idx];
                            if (!enc_chunk || !ind_chunk) {
                                weighted_value_chunk_sc[chunk_idx] = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                                continue;
                            }
                            auto v = enc_chunk->getCiphertext();
                            auto d = ind_chunk->getCiphertext();
                            weighted_value_chunk_sc[chunk_idx] = cc_comp->EvalMultAndRelinearize(v, d);
                            op_stats[0].eval_mult_ct_ct.fetch_add(1, std::memory_order_relaxed);
                            op_stats[0].eval_relinearize.fetch_add(1, std::memory_order_relaxed);
                            // enc_chunk freed here
                        }
                    }

                    // Single-context prefix caches (rns_level==1)
                    std::vector<Ciphertext<DCRTPoly>> sc_prefix_count_cache;
                    std::vector<Ciphertext<DCRTPoly>> sc_prefix_sum_cache;
                    if (kUsePrefixSum && rns_level == 1) {
                        if (agg_def.type == AggregateId::COUNT) {
                            size_t max_chunk = 0;
                            for (size_t g = 0; g < num_groups; ++g) {
                                size_t er = bin_metadata[g].original_end_row;
                                if (er > 0) max_chunk = std::max(max_chunk, (er - 1) / pack_slots);
                            }
                            sc_prefix_count_cache.resize(max_chunk + 1);
                            for (size_t ci = 0; ci <= max_chunk; ++ci) {
                                if (ci < dummy_tag_col->getFheChunks().size()) {
                                    auto chunk = dummy_tag_col->getFheChunks()[ci];
                                    if (chunk) {
                                        sc_prefix_count_cache[ci] =
                                            computePrefixSum(cc_comp, chunk->getCiphertext(), chunk->packed_count, 0);
                                    }
                                }
                            }
                        }
                        if (agg_def.type == AggregateId::SUM && !weighted_value_chunk_sc.empty()) {
                            sc_prefix_sum_cache.resize(weighted_value_chunk_sc.size());
                            for (size_t ci = 0; ci < weighted_value_chunk_sc.size(); ++ci) {
                                if (weighted_value_chunk_sc[ci]) {
                                    sc_prefix_sum_cache[ci] =
                                        computePrefixSum(cc_comp, weighted_value_chunk_sc[ci], pack_slots, 0);
                                }
                            }
                        }
                    }

                    #pragma omp parallel for schedule(static)
                    for (size_t group_idx = 0; group_idx < num_groups; ++group_idx) {
                    if (group_idx >= bin_metadata.size()) {
                        continue;
                    }
                    const auto& group_meta = bin_metadata[group_idx];
                    Ciphertext<DCRTPoly> group_result;

                    if (agg_def.type == AggregateId::COUNT) {
                        size_t start_row = group_meta.original_start_row;
                        size_t end_row_excl = group_meta.original_end_row;

                        if (rns_level == 1) {
                            size_t chunk_idx_out = group_idx / slots_per_chunk;
                            size_t target_slot = group_idx % slots_per_chunk;

                            if (kUsePrefixSum && !sc_prefix_count_cache.empty()) {
                                size_t start_chunk = start_row / pack_slots;
                                size_t end_chunk = (end_row_excl > 0) ? ((end_row_excl - 1) / pack_slots) : 0;
                                std::vector<Ciphertext<DCRTPoly>> partial_counts;
                                for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk; ++chunk_idx) {
                                    if (chunk_idx >= sc_prefix_count_cache.size() || !sc_prefix_count_cache[chunk_idx]) continue;
                                    size_t chunk_start_row = chunk_idx * pack_slots;
                                    auto dummy_chunk = dummy_tag_col->getFheChunks()[chunk_idx];
                                    size_t chunk_packed = dummy_chunk ? dummy_chunk->packed_count : pack_slots;
                                    size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                                    size_t range_end = (end_row_excl < chunk_start_row + chunk_packed)
                                        ? (end_row_excl - 1 - chunk_start_row) : (chunk_packed - 1);
                                    partial_counts.push_back(extractGroupSumFromPrefix(
                                        cc_comp, sc_prefix_count_cache[chunk_idx], range_start, range_end, target_slot, 0));
                                }
                                if (!partial_counts.empty()) {
                                    group_result = (partial_counts.size() == 1)
                                        ? std::move(partial_counts[0])
                                        : evalAddMany(cc_comp, std::move(partial_counts), 0);
                                } else {
                                    group_result = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                                }
                                int tid = omp_get_thread_num();
                                acc_single[tid][chunk_idx_out] = cc_comp->EvalAdd(acc_single[tid][chunk_idx_out], group_result);
                                op_stats[0].eval_add.fetch_add(1, std::memory_order_relaxed);
                            } else {
                            // COUNT = sum(dummy_tag) (1=valid); use EvalAddMany for chunk combination.
                            std::vector<Ciphertext<DCRTPoly>> count_chunks_sc;
                            size_t start_chunk = start_row / pack_slots;
                            size_t end_chunk = (end_row_excl > 0) ? ((end_row_excl - 1) / pack_slots) : 0;
                            size_t effective_slot_count_sc = 0;
                            for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk && chunk_idx < dummy_tag_col->getFheChunks().size(); ++chunk_idx) {
                                auto dummy_chunk = dummy_tag_col->getFheChunks()[chunk_idx];
                                if (!dummy_chunk) continue;
                                size_t chunk_start_row = chunk_idx * pack_slots;
                                size_t chunk_end_row_excl = chunk_start_row + dummy_chunk->packed_count;
                                size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                                size_t range_end = (end_row_excl < chunk_end_row_excl) ? (end_row_excl - 1 - chunk_start_row) : (dummy_chunk->packed_count - 1);
                                effective_slot_count_sc += (range_end - range_start + 1);
                                bool is_full_chunk = (range_start == 0 && range_end == pack_slots - 1);
                                auto chunk_ct = dummy_chunk->getCiphertext();
                                if (!is_full_chunk) {
                                    std::vector<int64_t> range_mask_vec(pack_slots, 0);
                                    for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) range_mask_vec[i] = 1;
                                    Plaintext range_mask_pt = cc_comp->MakePackedPlaintext(range_mask_vec);
                                    chunk_ct = cc_comp->EvalMult(chunk_ct, range_mask_pt);
                                    op_stats[0].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                                }
                                count_chunks_sc.push_back(std::move(chunk_ct));
                            }
                            if (!count_chunks_sc.empty()) {
                                Ciphertext<DCRTPoly> total_dummy_masked = (count_chunks_sc.size() == 1)
                                    ? std::move(count_chunks_sc[0])
                                    : evalAddMany(cc_comp, std::move(count_chunks_sc), 0);
                                // Opt: sum only [target_slot, max_range_end] instead of all pack_slots
                                size_t max_re_sc = 0;
                                for (size_t ci = start_chunk; ci <= end_chunk && ci < dummy_tag_col->getFheChunks().size(); ++ci) {
                                    auto dc = dummy_tag_col->getFheChunks()[ci];
                                    if (!dc) continue;
                                    size_t csr = ci * pack_slots;
                                    size_t re = (end_row_excl < csr + dc->packed_count) ? (end_row_excl - 1 - csr) : (dc->packed_count - 1);
                                    max_re_sc = std::max(max_re_sc, re);
                                }
                                size_t eff_len_sc = std::min(max_re_sc - target_slot + 1, pack_slots);
                                group_result = sumSlotsInRangeLength(cc_comp, total_dummy_masked, eff_len_sc, 0);
                            } else {
                                group_result = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                            }
                            int tid = omp_get_thread_num();
                            Plaintext mask_pt = cachedTargetMask(cc_comp, target_slot, pack_slots);
                            auto aligned_sum = cc_comp->EvalMult(group_result, mask_pt);
                            op_stats[0].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                            acc_single[tid][chunk_idx_out] = cc_comp->EvalAdd(acc_single[tid][chunk_idx_out], aligned_sum);
                            op_stats[0].eval_add.fetch_add(1, std::memory_order_relaxed);
                            }
                        } else {
                            // RNS COUNT: per-channel so count value fits (can exceed single modulus)
                            for (size_t ch = 0; ch < rns_level; ++ch) {
                                processCountRnsChannel(group_idx, ch);
                            }
                        }
                    } else if (agg_def.type == AggregateId::SUM) {
                        // SUM: sum encrypted values in group using bin metadata
                        const auto& col_bin_info = group_meta.column_bin_info.find(agg_col_name);
                        if (col_bin_info == group_meta.column_bin_info.end()) {
                            throw std::runtime_error("FheAggregate: bin info not found for column: " + agg_col_name);
                        }

                        if (rns_level == 1) {
                            size_t chunk_idx_out = group_idx / slots_per_chunk;
                            size_t target_slot = group_idx % slots_per_chunk;

                            if (kUsePrefixSum && !sc_prefix_sum_cache.empty()) {
                                std::vector<Ciphertext<DCRTPoly>> partial_sums;
                                for (size_t chunk_idx = col_bin_info->second.start_chunk_idx;
                                     chunk_idx <= col_bin_info->second.end_chunk_idx;
                                     ++chunk_idx) {
                                    const auto& chunk_range_it = col_bin_info->second.chunk_slot_ranges.find(chunk_idx);
                                    if (chunk_range_it == col_bin_info->second.chunk_slot_ranges.end()) continue;
                                    if (chunk_idx >= sc_prefix_sum_cache.size() || !sc_prefix_sum_cache[chunk_idx]) continue;
                                    size_t range_start = chunk_range_it->second.first;
                                    size_t range_end = chunk_range_it->second.second;
                                    partial_sums.push_back(extractGroupSumFromPrefix(
                                        cc_comp, sc_prefix_sum_cache[chunk_idx], range_start, range_end, target_slot, 0));
                                }
                                if (!partial_sums.empty()) {
                                    group_result = (partial_sums.size() == 1)
                                        ? std::move(partial_sums[0])
                                        : evalAddMany(cc_comp, std::move(partial_sums), 0);
                                } else {
                                    group_result = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                                }
                                int tid = omp_get_thread_num();
                                acc_single[tid][chunk_idx_out] = cc_comp->EvalAdd(acc_single[tid][chunk_idx_out], group_result);
                                op_stats[0].eval_add.fetch_add(1, std::memory_order_relaxed);
                            } else {
                            // Single-context SUM: Opt 1 use precomputed value×dummy per chunk.
                            std::vector<Ciphertext<DCRTPoly>> sum_chunks;
                            size_t effective_slot_count_sum_sc = 0;
                            for (size_t chunk_idx = col_bin_info->second.start_chunk_idx;
                                 chunk_idx <= col_bin_info->second.end_chunk_idx;
                                 ++chunk_idx) {
                                const auto& chunk_range_it = col_bin_info->second.chunk_slot_ranges.find(chunk_idx);
                                if (chunk_range_it == col_bin_info->second.chunk_slot_ranges.end()) continue;
                                size_t range_start = chunk_range_it->second.first;
                                size_t range_end = chunk_range_it->second.second;
                                effective_slot_count_sum_sc += (range_end - range_start + 1);
                                if (chunk_idx >= weighted_value_chunk_sc.size()) continue;
                                Ciphertext<DCRTPoly> chunk_ct = weighted_value_chunk_sc[chunk_idx];
                                bool is_full_chunk = (range_start == 0 && range_end == pack_slots - 1);
                                if (!is_full_chunk) {
                                    std::vector<int64_t> range_mask_vec(pack_slots, 0);
                                    for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) range_mask_vec[i] = 1;
                                    Plaintext range_mask_pt = cc_comp->MakePackedPlaintext(range_mask_vec);
                                    chunk_ct = cc_comp->EvalMult(chunk_ct, range_mask_pt);
                                    op_stats[0].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                                }
                                sum_chunks.push_back(std::move(chunk_ct));
                            }
                            if (!sum_chunks.empty()) {
                                Ciphertext<DCRTPoly> total_masked = (sum_chunks.size() == 1)
                                    ? std::move(sum_chunks[0])
                                    : evalAddMany(cc_comp, std::move(sum_chunks), 0);
                                // Opt: sum only [target_slot, max_range_end] instead of all pack_slots
                                size_t max_re_sum_sc = 0;
                                for (auto& [ci, range] : col_bin_info->second.chunk_slot_ranges) {
                                    max_re_sum_sc = std::max(max_re_sum_sc, range.second);
                                }
                                size_t eff_len_sum_sc = std::min(max_re_sum_sc - target_slot + 1, pack_slots);
                                group_result = sumSlotsInRangeLength(cc_comp, total_masked, eff_len_sum_sc, 0);
                            } else {
                                group_result = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                            }
                            int tid = omp_get_thread_num();
                            Plaintext mask_pt = cachedTargetMask(cc_comp, target_slot, pack_slots);
                            auto aligned_sum = cc_comp->EvalMult(group_result, mask_pt);
                            op_stats[0].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                            acc_single[tid][chunk_idx_out] = cc_comp->EvalAdd(acc_single[tid][chunk_idx_out], aligned_sum);
                            op_stats[0].eval_add.fetch_add(1, std::memory_order_relaxed);
                            }
                        } else {
                            // RNS: per-channel SUM
                            for (size_t ch = 0; ch < rns_level; ++ch) {
                                processSumRnsChannel(group_idx, ch);
                            }
                        }
                    }
                }
                }

                // Store encrypted results directly (no decryption)
                auto result_col = std::make_shared<FheColumn>(agg_def.alias);
                std::vector<int64_t> mask_vec(slots_per_chunk, 0);
                mask_vec[0] = 1;

                if (sum_uses_rns) {
                    for (size_t chunk_idx = 0; chunk_idx < num_packed_chunks; ++chunk_idx) {
                        size_t start_group = chunk_idx * slots_per_chunk;
                        size_t end_group = std::min(start_group + slots_per_chunk, num_groups);
                        size_t groups_in_chunk = end_group - start_group;
                        if (groups_in_chunk == 0 || start_group >= num_groups) continue;
                        std::vector<Ciphertext<DCRTPoly>> packed_per_channel(rns_level);
                        for (size_t ch = 0; ch < rns_level; ++ch) {
                            auto cc_ch = fhe_manager.getRnsContext(ch);
                            std::vector<Ciphertext<DCRTPoly>> to_merge;
                            to_merge.reserve(num_threads);
                            for (int t = 0; t < num_threads; ++t)
                                to_merge.push_back(acc_sum[t][chunk_idx][ch]);
                            packed_per_channel[ch] = (to_merge.size() == 1)
                                ? std::move(to_merge[0])
                                : evalAddMany(cc_ch, std::move(to_merge), ch);
                        }
                        QuantizationParams qp;
                        qp.simdSlots = slots_per_chunk;
                        FheTypeDescriptor td(FheDataType::LONG, FheEncodingType::BFV_PACKED_ENCODING);
                        result_col->addFheChunk(std::make_shared<FheColumnChunk>(packed_per_channel, qp, td, groups_in_chunk));
                    }
                } else if (count_uses_rns) {
                    for (size_t chunk_idx = 0; chunk_idx < num_packed_chunks; ++chunk_idx) {
                        size_t start_group = chunk_idx * slots_per_chunk;
                        size_t end_group = std::min(start_group + slots_per_chunk, num_groups);
                        size_t groups_in_chunk = end_group - start_group;
                        if (groups_in_chunk == 0 || start_group >= num_groups) continue;
                        std::vector<Ciphertext<DCRTPoly>> packed_per_channel(rns_level);
                        for (size_t ch = 0; ch < rns_level; ++ch) {
                            auto cc_ch = fhe_manager.getRnsContext(ch);
                            std::vector<Ciphertext<DCRTPoly>> to_merge;
                            to_merge.reserve(num_threads);
                            for (int t = 0; t < num_threads; ++t)
                                to_merge.push_back(acc_count[t][chunk_idx][ch]);
                            packed_per_channel[ch] = (to_merge.size() == 1)
                                ? std::move(to_merge[0])
                                : evalAddMany(cc_ch, std::move(to_merge), ch);
                        }
                        QuantizationParams qp;
                        qp.simdSlots = slots_per_chunk;
                        FheTypeDescriptor td(FheDataType::LONG, FheEncodingType::BFV_PACKED_ENCODING);
                        result_col->addFheChunk(std::make_shared<FheColumnChunk>(packed_per_channel, qp, td, groups_in_chunk));
                    }
                } else {
                    for (size_t chunk_idx = 0; chunk_idx < num_packed_chunks; ++chunk_idx) {
                        size_t start_group = chunk_idx * slots_per_chunk;
                        size_t end_group = std::min(start_group + slots_per_chunk, num_groups);
                        size_t groups_in_chunk = end_group - start_group;
                        if (groups_in_chunk == 0 || start_group >= num_groups) continue;
                        std::vector<Ciphertext<DCRTPoly>> to_merge;
                        to_merge.reserve(num_threads);
                        for (int t = 0; t < num_threads; ++t)
                            to_merge.push_back(acc_single[t][chunk_idx]);
                        auto packed_ct = (to_merge.size() == 1)
                            ? std::move(to_merge[0])
                            : evalAddMany(cc_comp, std::move(to_merge), 0);
                        QuantizationParams qp;
                        qp.simdSlots = slots_per_chunk;
                        FheTypeDescriptor td(FheDataType::LONG, FheEncodingType::BFV_PACKED_ENCODING);
                        result_col->addFheChunk(std::make_shared<FheColumnChunk>(packed_ct, qp, td, groups_in_chunk));
                    }
                }
                output->addColumn(result_col);
            }

            // Output dummy_tag = count per group (COUNT value). SCS interprets 0=dummy, non-zero=valid.
            // When we have a COUNT aggregate, reuse its column. Otherwise we must compute count (sum of dummy_tag) and use that.
            std::string count_alias;
            for (const auto& agg_def : working_aggregates) {
                if (agg_def.type == AggregateId::COUNT) {
                    count_alias = agg_def.alias;
                    break;
                }
            }
            std::shared_ptr<FheColumn> dummy_tag_out_col;
            if (!count_alias.empty()) {
                auto count_col = output->getFheColumn(count_alias);
                if (count_col) {
                    dummy_tag_out_col = std::make_shared<FheColumn>("dummy_tag");
                    for (const auto& chunk : count_col->getFheChunks()) {
                        dummy_tag_out_col->addFheChunk(chunk);
                    }
                }
            }
            if (!dummy_tag_out_col) {
                // No COUNT in aggregates: compute implicit count = sum(dummy_tag) per group and use for dummy_tag output.
                size_t rns_level_impl = fhe_manager.getRnsCount();
                if (rns_level_impl == 0) rns_level_impl = 1;
                input_->ensureEncrypted(dummy_tag_col->getName(), rns_level_impl);
                std::shared_ptr<FheColumn> ind_col_impl = (rns_level_impl > 1) ? input_->getFheColumn(dummy_tag_col->getName()) : dummy_tag_col;
                if (!ind_col_impl) ind_col_impl = dummy_tag_col;

                size_t slots_per_chunk = pack_slots;
                size_t num_packed_chunks = (num_groups + slots_per_chunk - 1) / slots_per_chunk;
                dummy_tag_out_col = std::make_shared<FheColumn>("dummy_tag");
                QuantizationParams qp_dt;
                qp_dt.simdSlots = static_cast<unsigned int>(slots_per_chunk);
                FheTypeDescriptor td_dt(FheDataType::LONG, FheEncodingType::BFV_PACKED_ENCODING);

                if (rns_level_impl == 1) {
                    // Opt 4: direct accumulation for implicit count (single channel)
                    const int num_threads_impl = omp_get_max_threads();
                    std::vector<std::vector<Ciphertext<DCRTPoly>>> acc_impl(num_threads_impl);
                    for (int t = 0; t < num_threads_impl; ++t) {
                        acc_impl[t].resize(num_packed_chunks);
                        for (size_t c = 0; c < num_packed_chunks; ++c)
                            acc_impl[t][c] = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                    }
                    // Prefix cache for implicit count (single channel)
                    std::vector<Ciphertext<DCRTPoly>> impl_prefix_cache;
                    if (kUsePrefixSum) {
                        size_t max_ci = 0;
                        for (size_t g = 0; g < num_groups; ++g) {
                            size_t er = bin_metadata[g].original_end_row;
                            if (er > 0) max_ci = std::max(max_ci, (er - 1) / pack_slots);
                        }
                        impl_prefix_cache.resize(max_ci + 1);
                        for (size_t ci = 0; ci <= max_ci && ci < ind_col_impl->getFheChunks().size(); ++ci) {
                            auto chunk = ind_col_impl->getFheChunks()[ci];
                            if (chunk) {
                                impl_prefix_cache[ci] =
                                    computePrefixSum(cc_comp, chunk->getCiphertext(), chunk->packed_count, 0);
                            }
                        }
                    }
                    #pragma omp parallel for schedule(static)
                    for (size_t group_idx = 0; group_idx < num_groups; ++group_idx) {
                        if (group_idx >= bin_metadata.size()) continue;
                        const auto& group_meta = bin_metadata[group_idx];
                        size_t start_row = group_meta.original_start_row;
                        size_t end_row_excl = group_meta.original_end_row;
                        size_t chunk_idx_out = group_idx / slots_per_chunk;
                        size_t target_slot = group_idx % slots_per_chunk;

                        if (kUsePrefixSum && !impl_prefix_cache.empty()) {
                            size_t start_chunk = start_row / pack_slots;
                            size_t end_chunk = (end_row_excl > 0) ? ((end_row_excl - 1) / pack_slots) : 0;
                            std::vector<Ciphertext<DCRTPoly>> partial_counts;
                            for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk; ++chunk_idx) {
                                if (chunk_idx >= impl_prefix_cache.size() || !impl_prefix_cache[chunk_idx]) continue;
                                size_t chunk_start_row = chunk_idx * pack_slots;
                                auto dummy_chunk = ind_col_impl->getFheChunks()[chunk_idx];
                                size_t chunk_packed = dummy_chunk ? dummy_chunk->packed_count : pack_slots;
                                size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                                size_t range_end = (end_row_excl < chunk_start_row + chunk_packed)
                                    ? (end_row_excl - 1 - chunk_start_row) : (chunk_packed - 1);
                                partial_counts.push_back(extractGroupSumFromPrefix(
                                    cc_comp, impl_prefix_cache[chunk_idx], range_start, range_end, target_slot, 0));
                            }
                            Ciphertext<DCRTPoly> count_ct;
                            if (!partial_counts.empty()) {
                                count_ct = (partial_counts.size() == 1)
                                    ? std::move(partial_counts[0])
                                    : evalAddMany(cc_comp, std::move(partial_counts), 0);
                            } else {
                                count_ct = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                            }
                            int tid = omp_get_thread_num();
                            acc_impl[tid][chunk_idx_out] = cc_comp->EvalAdd(acc_impl[tid][chunk_idx_out], count_ct);
                            op_stats[0].eval_add.fetch_add(1, std::memory_order_relaxed);
                        } else {
                        std::vector<Ciphertext<DCRTPoly>> impl_count_chunks;
                        size_t effective_slot_count_impl = 0;
                        size_t start_chunk = start_row / pack_slots;
                        size_t end_chunk = (end_row_excl > 0) ? ((end_row_excl - 1) / pack_slots) : 0;
                        for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk && chunk_idx < ind_col_impl->getFheChunks().size(); ++chunk_idx) {
                            auto dummy_chunk = ind_col_impl->getFheChunks()[chunk_idx];
                            if (!dummy_chunk) continue;
                            size_t chunk_start_row = chunk_idx * pack_slots;
                            size_t chunk_end_row_excl = chunk_start_row + dummy_chunk->packed_count;
                            size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                            size_t range_end = (end_row_excl < chunk_end_row_excl) ? (end_row_excl - 1 - chunk_start_row) : (dummy_chunk->packed_count - 1);
                            effective_slot_count_impl += (range_end - range_start + 1);
                            bool is_full_chunk = (range_start == 0 && range_end == pack_slots - 1);
                            auto chunk_ct = dummy_chunk->getCiphertext();
                            if (!is_full_chunk) {
                                std::vector<int64_t> range_mask_vec(pack_slots, 0);
                                for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) range_mask_vec[i] = 1;
                                Plaintext range_mask_pt = cc_comp->MakePackedPlaintext(range_mask_vec);
                                chunk_ct = cc_comp->EvalMult(chunk_ct, range_mask_pt);
                                op_stats[0].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                            }
                            impl_count_chunks.push_back(std::move(chunk_ct));
                        }
                        Ciphertext<DCRTPoly> count_ct;
                        if (!impl_count_chunks.empty()) {
                            Ciphertext<DCRTPoly> total_dummy_masked = (impl_count_chunks.size() == 1)
                                ? std::move(impl_count_chunks[0])
                                : evalAddMany(cc_comp, std::move(impl_count_chunks), 0);
                            // Opt: sum only [target_slot, max_range_end]
                            size_t max_re_impl = 0;
                            for (size_t ci = start_chunk; ci <= end_chunk && ci < ind_col_impl->getFheChunks().size(); ++ci) {
                                auto dc = ind_col_impl->getFheChunks()[ci];
                                if (!dc) continue;
                                size_t csr = ci * pack_slots;
                                size_t re = (end_row_excl < csr + dc->packed_count) ? (end_row_excl - 1 - csr) : (dc->packed_count - 1);
                                max_re_impl = std::max(max_re_impl, re);
                            }
                            size_t eff_len_impl = std::min(max_re_impl - target_slot + 1, pack_slots);
                            count_ct = sumSlotsInRangeLength(cc_comp, total_dummy_masked, eff_len_impl, 0);
                        } else {
                            count_ct = cachedZeroCi(cc_comp, pk_comp, pack_slots);
                        }
                        int tid = omp_get_thread_num();
                        Plaintext mask_pt = cachedTargetMask(cc_comp, target_slot, pack_slots);
                        auto aligned_sum = cc_comp->EvalMult(count_ct, mask_pt);
                        op_stats[0].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                        acc_impl[tid][chunk_idx_out] = cc_comp->EvalAdd(acc_impl[tid][chunk_idx_out], aligned_sum);
                        op_stats[0].eval_add.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                    for (size_t chunk_idx = 0; chunk_idx < num_packed_chunks; ++chunk_idx) {
                        size_t start_group = chunk_idx * slots_per_chunk;
                        size_t end_group = std::min(start_group + slots_per_chunk, num_groups);
                        size_t groups_in_chunk = end_group - start_group;
                        if (groups_in_chunk == 0 || start_group >= num_groups) continue;
                        std::vector<Ciphertext<DCRTPoly>> to_merge;
                        to_merge.reserve(num_threads_impl);
                        for (int t = 0; t < num_threads_impl; ++t) to_merge.push_back(acc_impl[t][chunk_idx]);
                        auto packed_ct = (to_merge.size() == 1) ? std::move(to_merge[0]) : evalAddMany(cc_comp, std::move(to_merge), 0);
                        dummy_tag_out_col->addFheChunk(std::make_shared<FheColumnChunk>(packed_ct, qp_dt, td_dt, groups_in_chunk));
                    }
                } else {
                    // Opt 4: direct accumulation for implicit count (multi-channel)
                    const int max_threads = omp_get_max_threads();
                    std::vector<std::vector<std::vector<Ciphertext<DCRTPoly>>>> acc_impl_count(max_threads);
                    for (int t = 0; t < max_threads; ++t) {
                        acc_impl_count[t].resize(num_packed_chunks);
                        for (size_t c = 0; c < num_packed_chunks; ++c) {
                            acc_impl_count[t][c].resize(rns_level_impl);
                            for (size_t ch = 0; ch < rns_level_impl; ++ch) {
                                auto cc_ch = fhe_manager.getRnsContext(ch);
                                auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                                acc_impl_count[t][c][ch] = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                            }
                        }
                    }
                    const bool low_par = (rns_level_impl > 1) && (num_groups < static_cast<size_t>(max_threads));
                    // Multi-channel prefix cache for implicit count
                    std::vector<std::vector<Ciphertext<DCRTPoly>>> impl_mc_prefix_cache;
                    if (kUsePrefixSum) {
                        size_t max_ci = 0;
                        for (size_t g = 0; g < num_groups; ++g) {
                            size_t er = bin_metadata[g].original_end_row;
                            if (er > 0) max_ci = std::max(max_ci, (er - 1) / pack_slots);
                        }
                        impl_mc_prefix_cache.resize(max_ci + 1);
                        for (auto& v : impl_mc_prefix_cache) v.resize(rns_level_impl);
                        #pragma omp parallel for schedule(dynamic)
                        for (size_t w = 0; w < (max_ci + 1) * rns_level_impl; ++w) {
                            size_t ci = w / rns_level_impl;
                            size_t ch = w % rns_level_impl;
                            if (ci < ind_col_impl->getFheChunks().size()) {
                                auto chunk = ind_col_impl->getFheChunks()[ci];
                                if (chunk) {
                                    auto cc_ch = fhe_manager.getRnsContext(ch);
                                    impl_mc_prefix_cache[ci][ch] =
                                        computePrefixSum(cc_ch, chunk->getCiphertext(ch), chunk->packed_count, ch);
                                }
                            }
                        }
                    }
                    auto runCountChannel = [&](size_t group_idx, size_t ch) {
                        if (group_idx >= bin_metadata.size()) return;
                        const auto& group_meta = bin_metadata[group_idx];
                        size_t start_row = group_meta.original_start_row;
                        size_t end_row_excl = group_meta.original_end_row;
                        size_t start_chunk = start_row / pack_slots;
                        size_t end_chunk = (end_row_excl > 0) ? ((end_row_excl - 1) / pack_slots) : 0;
                        auto cc_ch = fhe_manager.getRnsContext(ch);
                        auto pk_ch = fhe_manager.getRnsKeyPair(ch).publicKey;
                        size_t chunk_idx_out = group_idx / slots_per_chunk;
                        size_t target_slot = group_idx % slots_per_chunk;

                        if (kUsePrefixSum && !impl_mc_prefix_cache.empty()) {
                            std::vector<Ciphertext<DCRTPoly>> partial_counts;
                            for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk; ++chunk_idx) {
                                if (chunk_idx >= impl_mc_prefix_cache.size() ||
                                    ch >= impl_mc_prefix_cache[chunk_idx].size() ||
                                    !impl_mc_prefix_cache[chunk_idx][ch]) continue;
                                auto& prefix = impl_mc_prefix_cache[chunk_idx][ch];
                                size_t chunk_start_row = chunk_idx * pack_slots;
                                auto ind_chunk = ind_col_impl->getFheChunks()[chunk_idx];
                                size_t chunk_packed = ind_chunk ? ind_chunk->packed_count : pack_slots;
                                size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                                size_t range_end = (end_row_excl < chunk_start_row + chunk_packed)
                                    ? (end_row_excl - 1 - chunk_start_row) : (chunk_packed - 1);
                                partial_counts.push_back(extractGroupSumFromPrefix(
                                    cc_ch, prefix, range_start, range_end, target_slot, ch));
                            }
                            Ciphertext<DCRTPoly> count_ct;
                            if (!partial_counts.empty()) {
                                count_ct = (partial_counts.size() == 1)
                                    ? std::move(partial_counts[0])
                                    : evalAddMany(cc_ch, std::move(partial_counts), ch);
                            } else {
                                count_ct = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                            }
                            int tid = omp_get_thread_num();
                            acc_impl_count[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(acc_impl_count[tid][chunk_idx_out][ch], count_ct);
                            op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                            return;
                        }

                        Ciphertext<DCRTPoly> count_ct;
                        std::vector<Ciphertext<DCRTPoly>> count_chunks_impl;
                        size_t effective_slot_count_impl_ch = 0;
                        size_t max_range_end_impl_ch = 0;
                        for (size_t chunk_idx = start_chunk; chunk_idx <= end_chunk && chunk_idx < ind_col_impl->getFheChunks().size(); ++chunk_idx) {
                            auto dummy_chunk = ind_col_impl->getFheChunks()[chunk_idx];
                            if (!dummy_chunk) continue;
                            size_t chunk_start_row = chunk_idx * pack_slots;
                            size_t range_start = (start_row > chunk_start_row) ? (start_row - chunk_start_row) : 0;
                            size_t range_end = (end_row_excl < chunk_start_row + dummy_chunk->packed_count) ? (end_row_excl - 1 - chunk_start_row) : (dummy_chunk->packed_count - 1);
                            effective_slot_count_impl_ch += (range_end - range_start + 1);
                            if (range_end > max_range_end_impl_ch) max_range_end_impl_ch = range_end;
                            bool is_full_chunk = (range_start == 0 && range_end == pack_slots - 1);
                            auto chunk_ct = dummy_chunk->getCiphertext(ch);
                            if (!is_full_chunk) {
                                std::vector<int64_t> range_mask_vec(pack_slots, 0);
                                for (size_t i = range_start; i <= range_end && i < pack_slots; ++i) range_mask_vec[i] = 1;
                                Plaintext range_mask_pt = cc_ch->MakePackedPlaintext(range_mask_vec);
                                chunk_ct = cc_ch->EvalMult(chunk_ct, range_mask_pt);
                                op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                            }
                            count_chunks_impl.push_back(std::move(chunk_ct));
                        }
                        if (!count_chunks_impl.empty()) {
                            Ciphertext<DCRTPoly> total_dummy_masked_ch = (count_chunks_impl.size() == 1)
                                ? std::move(count_chunks_impl[0])
                                : evalAddMany(cc_ch, std::move(count_chunks_impl), ch);
                            size_t effective_len = std::min(max_range_end_impl_ch - target_slot + 1, pack_slots);
                            if (effective_len == 0) effective_len = pack_slots;
                            count_ct = sumSlotsInRangeLength(cc_ch, total_dummy_masked_ch, effective_len, ch);
                        } else {
                            count_ct = cachedZeroCi(cc_ch, pk_ch, pack_slots);
                        }
                        int tid = omp_get_thread_num();
                        Plaintext mask_pt_ch = cachedTargetMask(cc_ch, target_slot, pack_slots);
                        auto aligned_sum = cc_ch->EvalMult(count_ct, mask_pt_ch);
                        op_stats[ch].eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed);
                        acc_impl_count[tid][chunk_idx_out][ch] = cc_ch->EvalAdd(acc_impl_count[tid][chunk_idx_out][ch], aligned_sum);
                        op_stats[ch].eval_add.fetch_add(1, std::memory_order_relaxed);
                    };
                    if (low_par) {
                        const size_t total_work = num_groups * rns_level_impl;
                        #pragma omp parallel for schedule(static)
                        for (size_t work_idx = 0; work_idx < total_work; ++work_idx) {
                            size_t g = work_idx / rns_level_impl;
                            size_t ch = work_idx % rns_level_impl;
                            runCountChannel(g, ch);
                        }
                    } else {
                        #pragma omp parallel for schedule(static)
                        for (size_t group_idx = 0; group_idx < num_groups; ++group_idx) {
                            for (size_t ch = 0; ch < rns_level_impl; ++ch) runCountChannel(group_idx, ch);
                        }
                    }
                    for (size_t chunk_idx = 0; chunk_idx < num_packed_chunks; ++chunk_idx) {
                        size_t start_group = chunk_idx * slots_per_chunk;
                        size_t end_group = std::min(start_group + slots_per_chunk, num_groups);
                        size_t groups_in_chunk = end_group - start_group;
                        if (groups_in_chunk == 0 || start_group >= num_groups) continue;
                        std::vector<Ciphertext<DCRTPoly>> packed_per_channel(rns_level_impl);
                        for (size_t ch = 0; ch < rns_level_impl; ++ch) {
                            auto cc_ch = fhe_manager.getRnsContext(ch);
                            std::vector<Ciphertext<DCRTPoly>> to_merge;
                            to_merge.reserve(max_threads);
                            for (int t = 0; t < max_threads; ++t) to_merge.push_back(acc_impl_count[t][chunk_idx][ch]);
                            packed_per_channel[ch] = (to_merge.size() == 1) ? std::move(to_merge[0]) : evalAddMany(cc_ch, std::move(to_merge), ch);
                        }
                        dummy_tag_out_col->addFheChunk(std::make_shared<FheColumnChunk>(packed_per_channel, qp_dt, td_dt, groups_in_chunk));
                    }
                }
            }
            output->addColumn(dummy_tag_out_col);
            output->setDummyTagColumn(dummy_tag_out_col);

            printAggregateChannelStats(op_stats);
            this->output_ = output;
            return this->output_;
        }

        OperatorType FheAggregate::getType() const {
            return OperatorType::FHE_AGGREGATE;
        }

        std::string FheAggregate::getParameters() const {
            std::string result = "GROUP BY (";
            for (size_t i = 0; i < group_by_ordinals_.size(); ++i) {
                if (i > 0) result += ", ";
                result += std::to_string(group_by_ordinals_[i]);
            }
            result += ") ";
            for (size_t i = 0; i < aggregate_definitions_.size(); ++i) {
                if (i > 0) result += ", ";
                result += ScalarAggregateDefinition::getAggregatorString(aggregate_definitions_[i].type);
                result += "(" + std::to_string(aggregate_definitions_[i].ordinal) + ")";
            }
            return result;
        }

    } // namespace vaultdb
