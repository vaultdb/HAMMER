#ifndef _FHE_FILTER_H_
#define _FHE_FILTER_H_

#include "openfhe.h"
#include <operators/columnar/column_operator.h>
#include <query_table/columnar/fhe_column_table.h>
#include <expression/simd/simd_generic_expression.h>
#include <query_table/query_schema.h>
#include <string>
#include <vector>

namespace vaultdb {

    // Lightweight stats for comparison operations (per run)
    struct ComparisonStats {
        size_t eval_mult_count = 0;
        size_t eval_rotate_count = 0;
        size_t ciphertext_count = 0;
        size_t relinearize_count = 0;
        // Phase A: detailed counters for comparator cost analysis
        size_t eval_add_count = 0;
        size_t eval_sub_count = 0;
        size_t rescale_count = 0;      // ModReduce/Rescale (BFV level consumption)
        size_t digit_compare_call_count = 0;  // AtomicComparator invocations per digit
        size_t poly_eval_gt_count = 0;  // EvaluatePolyAdaptive(use_neg=false) calls
        size_t poly_eval_lt_count = 0;  // EvaluatePolyAdaptive(use_neg=true) calls
    };

    // DNF (OR-of-AND) group definition: each group is a conjunction of predicates,
    // and groups are OR'd together, then AND'd with the main (common) predicates.
    struct DnfGroupDef {
        std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> threshold_digits;
        std::vector<std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>>> threshold_digits_per_channel;
        std::vector<std::string> column_names;
        std::vector<size_t> radix_bases;
        std::vector<std::string> predicate_types;
        std::vector<int> or_group_ids;  // for IN within group (CNF inside each AND-group)
    };

    class FheFilter : public ColumnOperator<void> {
    private:
        std::shared_ptr<FheColumnTable> input_;  // Cached input table (set in runSelf)
        std::string indicator_name_;
        std::vector<SIMDFheGenericExpression> predicates_;
        
        // For deferred predicate creation (used when predicates provided later or need schema)
        std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> deferred_threshold_digits_;
        std::vector<std::string> deferred_column_names_;
        std::vector<size_t> deferred_radix_bases_;
        std::vector<std::string> deferred_predicate_types_;  // "less_equal", "less_than", "greater_equal", "greater_than"
        /// Per-channel threshold for multi-channel dummy_tag (SUM); empty or [0].size()<=1 = single-channel only
        std::vector<std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>>> deferred_threshold_digits_per_channel_;
        /// Predicates per channel (built in runSelf when multi-channel); predicates_per_channel_[ch][pred_idx]
        std::vector<std::vector<SIMDFheGenericExpression>> predicates_per_channel_;
        /// OR group IDs: predicates with the same ID are combined via EvalAdd (OR);
        /// different IDs are combined via EvalMult (AND). Empty = all AND (backward compat).
        std::vector<int> or_group_ids_;
        /// DNF groups: each group is AND'd internally, then all groups OR'd, then AND'd with main predicates.
        std::vector<DnfGroupDef> dnf_groups_;

        // --- State set by preparePredicates(), used by computeChunkIndicator() ---
        bool predicates_prepared_ = false;
        std::shared_ptr<PlainColumnTable> prepared_plain_snapshot_;
        std::shared_ptr<FheColumn> prepared_existing_dummy_tag_;
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> prepared_ones_cipher_shared_;
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> prepared_ones_cipher_rns_;
        size_t prepared_pack_slots_ = 0;
        size_t prepared_row_count_ = 0;
        size_t prepared_chunk_count_ = 0;
        bool prepared_use_multi_channel_ = false;
        // DNF group predicates (built from dnf_groups_ in preparePredicates)
        std::vector<std::vector<SIMDFheGenericExpression>> prepared_dnf_group_predicates_;
        std::vector<std::vector<std::vector<SIMDFheGenericExpression>>> prepared_dnf_group_predicates_per_channel_;
        std::vector<std::vector<int>> prepared_dnf_group_or_ids_;

    public:
        FheFilter(ColumnOperator<void>* child,
                  const std::vector<SIMDFheGenericExpression>& predicates,
                  std::string indicator_name = "dummy_tag");
        
        // Constructor accepting shared_ptr<FheColumnTable> directly (for testing convenience)
        FheFilter(std::shared_ptr<FheColumnTable> input_table,
                  const std::vector<SIMDFheGenericExpression>& predicates,
                  std::string indicator_name = "dummy_tag");
        
        // Constructor for deferred predicate creation
        FheFilter(ColumnOperator<void>* child,
                  const std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>>& threshold_digits,
                  const std::vector<std::string>& column_names,
                  const std::vector<size_t>& radix_bases,
                  const std::vector<std::string>& predicate_types = {},  // default: all "less_equal"
                  std::string indicator_name = "dummy_tag",
                  const std::vector<std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>>>& threshold_digits_per_channel = {},
                  const std::vector<int>& or_group_ids = {});

        std::shared_ptr<ColumnTableBase<void>> runSelf();

        /// One-time predicate setup: builds threshold ciphertexts, DNF groups, ones_cipher.
        /// Idempotent — safe to call multiple times.
        /// Must be called before computeChunkIndicator().
        void preparePredicates();

        /// Compute filter indicator for a single chunk.
        /// Returns an FheColumnChunk containing the dummy_tag ciphertexts for chunk_idx.
        /// Thread-safe for different chunk_idx values simultaneously.
        std::shared_ptr<FheColumnChunk> computeChunkIndicator(size_t chunk_idx);

        /// Number of chunks in the input table.
        size_t getChunkCount() const;

        /// Access to plain snapshot (for FheAggregate's encryptSingleChunk).
        std::shared_ptr<PlainColumnTable> getPlainSnapshot() const;

        /// Access to bin_metadata (for FheAggregate group processing).
        const std::vector<BinGroupMetadata>& getBinMetadata() const;
        const std::vector<int32_t>& getBinGroupByOrdinals() const;

        /// Access to the input FheColumnTable (for dummy_tag, schema, etc.)
        std::shared_ptr<FheColumnTable> getInputTable() const { return input_; }

        void setDnfGroups(const std::vector<DnfGroupDef>& groups) { dnf_groups_ = groups; }

        OperatorType getType() const override;

        std::string getParameters() const override;

        void updateCollation() override {}
    };

    enum class FheFilterStyle {
        PolynomialLE,   // Less or Equal (A <= B)
        PolynomialLT,   // Less Than (A < B)
        PolynomialGE,   // Greater or Equal (A >= B)
        PolynomialGT,   // Greater Than (A > B)
        PolynomialEQ    // Equal (A = B), for enum: single EQ or EQ[0]*EQ[1]*...*EQ[n-1]
    };

    // Less or Equal: A <= B. rns_channel = (size_t)-1 means use comparison context.
    SIMDFheGenericExpression makePolynomialLessEqualPredicate(const QuerySchema& schema,
                                                              const std::string& column_name,
                                                              const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& threshold_digits,
                                                              size_t radix_base = 8,
                                                              size_t rns_channel = static_cast<size_t>(-1));

    // Less Than: A < B
    SIMDFheGenericExpression makePolynomialLessThanPredicate(const QuerySchema& schema,
                                                             const std::string& column_name,
                                                             const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& threshold_digits,
                                                             size_t radix_base = 8,
                                                             size_t rns_channel = static_cast<size_t>(-1));

    // Greater or Equal: A >= B
    SIMDFheGenericExpression makePolynomialGreaterEqualPredicate(const QuerySchema& schema,
                                                                 const std::string& column_name,
                                                                 const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& threshold_digits,
                                                                 size_t radix_base = 8,
                                                                 size_t rns_channel = static_cast<size_t>(-1));

    // Greater Than: A > B
    SIMDFheGenericExpression makePolynomialGreaterThanPredicate(const QuerySchema& schema,
                                                                const std::string& column_name,
                                                                const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& threshold_digits,
                                                                size_t radix_base = 8,
                                                                size_t rns_channel = static_cast<size_t>(-1));

    // Equal: A = B (for enum columns)
    SIMDFheGenericExpression makePolynomialEqualPredicate(const QuerySchema& schema,
                                                          const std::string& column_name,
                                                          const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& threshold_digits,
                                                          size_t radix_base = 8,
                                                          size_t rns_channel = static_cast<size_t>(-1));

    // Stats getters (populated during comparison)
    ComparisonStats getPolynomialComparisonStats();
    void resetComparisonStats();

    /// Phase A: enable detailed comparator stats (EvalMult/Rot/Relin/digit_compare etc).
    /// Call with true when --cmp_stats is passed. CI/tests can toggle for reproducible measurement.
    void setComparatorStatsEnabled(bool enabled);
    bool isComparatorStatsEnabled();

    /// Print detailed ComparisonStats to stdout (when enabled). For Gate 0 artifacts.
    void printComparatorStats(const ComparisonStats& stats, const char* label = "Comparator");

}  // namespace vaultdb

#endif  // _FHE_FILTER_H_
