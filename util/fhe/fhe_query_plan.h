#pragma once

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <util/fhe/fhe_thread_cost_model.h>

namespace vaultdb {

// ════════════════════════════════════════════════════════════════════
// Phase A — Depth Computation
// ════════════════════════════════════════════════════════════════════

struct PredicateDepthInfo {
    int radix_base;
    int num_digits;
};

struct QueryPredicateProfile {
    std::string query_name;
    std::vector<PredicateDepthInfo> predicates;                    // from "predicate"/"predicates"
    std::vector<std::vector<PredicateDepthInfo>> dnf_groups;       // from "orPredicateGroups"
    bool has_dnf = false;
};

// Per-predicate multiplicative depth (matches AtomicComparatorTernary):
//   phase_A    = ceil(log2(base-1)) + 1    (odd power chain)
//   phase_C    = 1                          (T² squaring)
//   lex_merge  = ceil(log2(digits))         (lexicographic tree reduction)
// Special case: base=2 → phase_A=0 (identity, no odd-power evaluation)
inline int computePredicateDepth(int base, int digits) {
    int phase_A = (base <= 2) ? 0
                 : static_cast<int>(std::ceil(std::log2(base - 1))) + 1;
    int phase_C = 1;
    int lex_merge = (digits <= 1) ? 0
                   : static_cast<int>(std::ceil(std::log2(digits)));
    return phase_A + phase_C + lex_merge;
}

// v3: Algorithmic lower bound — no safety margins.
// d_lb = max(per_predicate_depth) + ceil(log2(num_and_terms)) + d_agg(1)
inline int computeAlgorithmicLB(const QueryPredicateProfile& profile) {
    int max_pred_depth = 0;
    int total_and_terms = 0;

    // Top-level predicates
    for (const auto& p : profile.predicates) {
        int d = computePredicateDepth(p.radix_base, p.num_digits);
        max_pred_depth = std::max(max_pred_depth, d);
    }
    total_and_terms += static_cast<int>(profile.predicates.size());

    // DNF groups
    for (const auto& group : profile.dnf_groups) {
        for (const auto& p : group) {
            int d = computePredicateDepth(p.radix_base, p.num_digits);
            max_pred_depth = std::max(max_pred_depth, d);
        }
        total_and_terms += 1;  // each OR group output is one AND-tree input
    }

    int and_tree_depth = (total_and_terms <= 1) ? 0
                        : static_cast<int>(std::ceil(std::log2(total_and_terms)));
    int d_agg = 1;  // EvalMult(value_CT, indicator_CT)

    return max_pred_depth + and_tree_depth + d_agg;
}

// Legacy wrapper for backward compat
inline int computeMinMultDepth(const QueryPredicateProfile& profile) {
    return computeAlgorithmicLB(profile) + 2;  // +1 agg +1 safety (legacy)
}

// Parse query JSON to extract predicate radix/digit info from FheFilter operators.
// Handles: singular "predicate", array "predicates", and "orPredicateGroups".
inline QueryPredicateProfile parseQueryPredicateProfile(
        const std::string& query_name,
        const std::string& plan_json_path) {
    QueryPredicateProfile profile;
    profile.query_name = query_name;

    boost::property_tree::ptree root;
    try {
        boost::property_tree::read_json(plan_json_path, root);
    } catch (const std::exception& e) {
        std::cerr << "[QueryPlan] WARNING: cannot parse " << plan_json_path
                  << ": " << e.what() << std::endl;
        return profile;
    }

    auto rels = root.get_child_optional("rels");
    if (!rels) return profile;

    for (const auto& rel_pair : *rels) {
        const auto& rel = rel_pair.second;
        auto relOp = rel.get_optional<std::string>("relOp");
        if (!relOp || *relOp != "FheFilter") continue;

        // Singular predicate
        auto pred = rel.get_child_optional("predicate");
        if (pred) {
            int base = pred->get<int>("radixBase", 4);
            int digits = pred->get<int>("numDigits", 6);
            profile.predicates.push_back({base, digits});
        }

        // Array of predicates
        auto preds = rel.get_child_optional("predicates");
        if (preds) {
            for (const auto& p_pair : *preds) {
                int base = p_pair.second.get<int>("radixBase", 4);
                int digits = p_pair.second.get<int>("numDigits", 6);
                profile.predicates.push_back({base, digits});
            }
        }

        // DNF groups
        auto or_groups = rel.get_child_optional("orPredicateGroups");
        if (or_groups) {
            profile.has_dnf = true;
            for (const auto& group_pair : *or_groups) {
                std::vector<PredicateDepthInfo> group_preds;
                auto group_predicates = group_pair.second.get_child_optional("predicates");
                if (group_predicates) {
                    for (const auto& gp_pair : *group_predicates) {
                        int base = gp_pair.second.get<int>("radixBase", 4);
                        int digits = gp_pair.second.get<int>("numDigits", 6);
                        group_preds.push_back({base, digits});
                    }
                }
                profile.dnf_groups.push_back(std::move(group_preds));
            }
        }
    }

    return profile;
}


// ════════════════════════════════════════════════════════════════════
// Phase B — FHE Parameter Selection (v3: empirical depth + candidates)
// ════════════════════════════════════════════════════════════════════

// Empirical minimum passing (ring_dim, mult_depth) per query.
// Confirmed by 3-party validation at SF1500 and SF15000.
struct EmpiricalEntry {
    uint32_t ring_dim;
    int      mult_depth;
};

inline const std::map<std::string, EmpiricalEntry>& kEmpiricalMinDepth() {
    static const std::map<std::string, EmpiricalEntry> table = {
        {"q1",  {32768, 11}},
        {"q4",  {32768, 11}},
        {"q5",  {65536, 14}},  // 25 groups exhaust ch0 noise budget at (32768,13)
        {"q6",  {65536, 14}},  // depth=13 fails; depth=14 needs 65536 for security
        {"q12", {65536, 14}},  // d_lb=10, (32768,13) gives L_eff=10 → zero noise margin → fails
        {"q19", {65536, 14}},  // same depth class as Q12
    };
    return table;
}

// Formula-based estimate for unknown queries
inline int computeMPred(int d_lb) {
    return d_lb + 2;
}

// Actual mult_depth to use: empirical if known, else formula + safety
inline int getMUse(const std::string& query_name, uint32_t ring_dim, int d_lb) {
    const auto& table = kEmpiricalMinDepth();
    auto it = table.find(query_name);
    if (it != table.end() && it->second.ring_dim == ring_dim) {
        return it->second.mult_depth;
    }
    return computeMPred(d_lb) + 1;  // unknown: conservative
}

// OpenFHE security constraint: max mult_depth for each ring_dim (HYBRID key switching)
inline bool openFHESecurityAccepts(uint32_t ring_dim, int mult_depth) {
    if (ring_dim == 32768 && mult_depth > 13) return false;
    if (ring_dim == 65536 && mult_depth > 18) return false;
    return true;
}

// Empirical validation: reject known-failing (query, N, m) combinations
inline bool validationPasses(const std::string& qname, uint32_t N, int m) {
    const auto& table = kEmpiricalMinDepth();
    auto it = table.find(qname);
    if (it != table.end()) {
        if (N < it->second.ring_dim) return false;
        if (m < it->second.mult_depth) return false;
    }
    return true;
}

struct FHECandidate {
    uint32_t ring_dim;
    int      mult_depth;
    int      d_lb;
};

// ════════════════════════════════════════════════════════════════════
// Phase C — Size Model (moved before buildCandidates which uses getLEff)
// ════════════════════════════════════════════════════════════════════

// Empirical L_eff lookup: (ring_dim, mult_depth) → max tower count across RNS channels.
// Measured with HYBRID key switching on OpenFHE 1.4.
inline const std::map<std::pair<uint32_t, int>, int>& kLEffTable() {
    static const std::map<std::pair<uint32_t, int>, int> table = {
        {{32768, 11},  8},   // Q1, Q4
        {{32768, 12},  9},   // E4 base=16
        {{32768, 13}, 10},   // Q12, Q19
        {{65536, 13}, 11},   // baseline
        {{65536, 14}, 12},   // Q5, Q6
        {{65536, 15}, 13},   // future
    };
    return table;
}

inline int getLEff(uint32_t ring_dim, int mult_depth) {
    const auto& table = kLEffTable();
    auto it = table.find({ring_dim, mult_depth});
    if (it != table.end()) return it->second;
    // Fallback: HYBRID overhead approximation (empirical: 32768→3, 65536→2)
    int overhead = (ring_dim <= 32768) ? 3 : 2;
    return mult_depth - overhead;
}

// Build feasible candidate set — NOT greedy smallest-N
inline std::vector<FHECandidate> buildCandidates(
        const std::string& query_name, int d_lb) {
    std::vector<FHECandidate> candidates;

    for (uint32_t N : {32768u, 65536u}) {
        int m = getMUse(query_name, N, d_lb);
        // Bump mult_depth if L_eff insufficient for d_lb
        while (getLEff(N, m) < d_lb && openFHESecurityAccepts(N, m + 1)) {
            m++;
        }
        if (getLEff(N, m) < d_lb) continue;  // this ring_dim can't provide enough depth
        if (!openFHESecurityAccepts(N, m)) continue;
        if (!validationPasses(query_name, N, m)) continue;
        candidates.push_back({N, m, d_lb});
    }

    return candidates;
}

// Legacy wrapper (used by existing code)
inline size_t getLTowersMax(uint32_t ring_dim, uint32_t mult_depth) {
    return static_cast<size_t>(getLEff(ring_dim, static_cast<int>(mult_depth)));
}

inline size_t ctBytes(uint32_t ring_dim, int mult_depth) {
    int L = getLEff(ring_dim, mult_depth);
    return static_cast<size_t>(2) * ring_dim * 8 * L;  // 2 polys × N × 8 bytes × L towers
}

inline double workingSetFilter(uint32_t N, int m, double beta_f) {
    return beta_f * static_cast<double>(ctBytes(N, m));
}

inline double workingSetAgg(uint32_t N, int m, double beta_a) {
    return beta_a * static_cast<double>(ctBytes(N, m));
}


// ════════════════════════════════════════════════════════════════════
// Phase E — QueryExecutionPlan (v3: rho-based)
// ════════════════════════════════════════════════════════════════════

struct QueryExecutionPlan {
    // Depth analysis
    int d_lb = 0;              // algorithmic lower bound (no safety margins)
    int filter_depth = 0;
    int total_depth = 0;       // legacy: d_lb + 2
    bool rotation_noise_flag = false;

    // FHE parameters
    uint32_t ring_dim = 32768;
    uint32_t mult_depth = 13;
    size_t ct_size_bytes = 0;
    size_t working_set_filter_bytes = 0;
    size_t working_set_agg_bytes = 0;

    // v3: continuous cache pressure
    double rho_filter = 0.0;     // working_set_filter / L3
    double rho_agg = 0.0;        // working_set_agg / L3
    bool used_empirical_depth = false;

    // Legacy compat
    bool fits_l3 = false;

    // Thread allocation (defaults; actual T* computed at runtime with real work_items)
    int T_filter = 0;
    int T_agg = 0;

    // Diagnostics
    std::string query_name;
};

// Global singleton — set once at query startup before parallel execution.
inline QueryExecutionPlan& mutableCurrentQueryPlan() {
    static QueryExecutionPlan instance;
    return instance;
}

inline void setCurrentQueryPlan(const QueryExecutionPlan& plan) {
    mutableCurrentQueryPlan() = plan;
}

inline const QueryExecutionPlan& getCurrentQueryPlan() {
    return mutableCurrentQueryPlan();
}

// ════════════════════════════════════════════════════════════════════
// Phase D — Deterministic SMT Policy (no calibration needed)
// ════════════════════════════════════════════════════════════════════

// Simple deterministic SMT policy — T*, H, L3 read from hardware.
// No pi/gamma/base_ms calibration required.
//
//   if query is tiny-W (W < P) or DNF: T* = min(W, P)
//   elif rho < 1.05:                    T* = H  (LLC-fit)
//   else:                               T* = P  (DRAM-bound)
inline int selectThreadCount(
    size_t work_items,
    bool   has_dnf,
    size_t working_set_bytes,
    int    physical_cores,
    int    logical_cores,
    size_t l3_cache_bytes)
{
    // Exception 1: tiny-workload (W < P) or DNF
    if (has_dnf || work_items < static_cast<size_t>(physical_cores)) {
        return std::min(static_cast<int>(work_items), physical_cores);
    }

    // Core decision: LLC-fit → H, spill → P
    double rho = (l3_cache_bytes > 0)
               ? static_cast<double>(working_set_bytes)
                 / static_cast<double>(l3_cache_bytes)
               : 2.0;  // no L3 info → assume spill

    constexpr double kLLCThreshold = 1.05;

    if (rho < kLLCThreshold) {
        return logical_cores;   // LLC-fit: full SMT
    } else {
        return physical_cores;  // DRAM-bound: physical only
    }
}

// Log the SMT decision rationale
inline void logSmtDecision(const char* tag, int T_star,
                            double rho, size_t ws_bytes, size_t l3_bytes,
                            size_t work_items, int physical_cores, bool is_tiny) {
    double ws_mb = static_cast<double>(ws_bytes) / (1024.0 * 1024.0);
    double l3_mb = static_cast<double>(l3_bytes) / (1024.0 * 1024.0);
    std::cout << std::fixed << std::setprecision(2);
    if (is_tiny) {
        std::cout << "[QueryPlan/" << tag << "] SMT: rho=" << rho
                  << " -> T*=" << T_star
                  << " (tiny-W: W=" << work_items << " < P=" << physical_cores << ")"
                  << std::endl;
    } else if (rho < 1.05) {
        std::cout << "[QueryPlan/" << tag << "] SMT: rho=" << rho
                  << " -> T*=" << T_star
                  << " (LLC-fit: ws=" << ws_mb << "MB < L3=" << l3_mb << "MB x 1.05)"
                  << std::endl;
    } else {
        std::cout << "[QueryPlan/" << tag << "] SMT: rho=" << rho
                  << " -> T*=" << T_star
                  << " (DRAM-bound: ws=" << ws_mb << "MB > L3=" << l3_mb << "MB x 1.05)"
                  << std::endl;
    }
}

// Regime string for logging
inline std::string rhoRegime(double rho) {
    if (rho <= 0.9) return "fit";
    if (rho >= 1.2) return "spill";
    return "transition";
}

// Build the full query execution plan (v3).
inline QueryExecutionPlan buildQueryPlan(
        const std::string& query_name,
        const std::string& plan_json_path,
        const ServerProfile& sp) {
    QueryExecutionPlan plan;
    plan.query_name = query_name;

    // Step 1: Parse predicates and compute depth
    auto profile = parseQueryPredicateProfile(query_name, plan_json_path);
    plan.d_lb = computeAlgorithmicLB(profile);
    plan.total_depth = plan.d_lb + 2;  // legacy compat
    plan.filter_depth = plan.d_lb;     // d_lb already includes d_agg(1)

    // Step 2: Build candidates and pick smallest CT size
    auto candidates = buildCandidates(query_name, plan.d_lb);

    if (candidates.empty()) {
        // Fallback: use largest ring_dim with formula depth
        plan.ring_dim = 65536;
        plan.mult_depth = computeMPred(plan.d_lb) + 1;
    } else {
        // Pick candidate with smallest CT size
        size_t best_ct = std::numeric_limits<size_t>::max();
        for (const auto& c : candidates) {
            size_t ct = ctBytes(c.ring_dim, c.mult_depth);
            if (ct < best_ct) {
                best_ct = ct;
                plan.ring_dim = c.ring_dim;
                plan.mult_depth = static_cast<uint32_t>(c.mult_depth);
            }
        }
    }

    // Check if empirical depth was used
    const auto& emp = kEmpiricalMinDepth();
    auto emp_it = emp.find(query_name);
    plan.used_empirical_depth = (emp_it != emp.end() &&
                                  emp_it->second.ring_dim == plan.ring_dim &&
                                  emp_it->second.mult_depth == static_cast<int>(plan.mult_depth));

    // Step 3: Compute CT size and working sets
    // ws = 3 × ct_bytes (fixed multiplier, no calibrated beta)
    plan.ct_size_bytes = ctBytes(plan.ring_dim, plan.mult_depth);
    constexpr double kBetaFilter = 3.0;
    constexpr double kBetaAgg    = 2.0;
    plan.working_set_filter_bytes = static_cast<size_t>(
        workingSetFilter(plan.ring_dim, plan.mult_depth, kBetaFilter));
    plan.working_set_agg_bytes = static_cast<size_t>(
        workingSetAgg(plan.ring_dim, plan.mult_depth, kBetaAgg));

    // Step 4: Compute rho (cache pressure) = ws / L3
    if (sp.is_loaded && sp.l3_cache_bytes > 0) {
        double l3 = static_cast<double>(sp.l3_cache_bytes);
        plan.rho_filter = static_cast<double>(plan.working_set_filter_bytes) / l3;
        plan.rho_agg    = static_cast<double>(plan.working_set_agg_bytes) / l3;
        plan.fits_l3 = (plan.rho_filter <= 1.05);  // legacy compat
        plan.T_filter = sp.physical_cores;
        plan.T_agg    = sp.physical_cores;
    }

    plan.rotation_noise_flag = (plan.ring_dim == 65536);

    return plan;
}

// Formatted log block (v3)
inline void printQueryPlan(const QueryExecutionPlan& plan, const ServerProfile& sp) {
    double ct_mb = static_cast<double>(plan.ct_size_bytes) / (1024.0 * 1024.0);
    double ws_f_mb = static_cast<double>(plan.working_set_filter_bytes) / (1024.0 * 1024.0);
    double ws_a_mb = static_cast<double>(plan.working_set_agg_bytes) / (1024.0 * 1024.0);
    double l3_mb = static_cast<double>(sp.l3_cache_bytes) / (1024.0 * 1024.0);

    std::cout << "[QueryPlan] ════════════════════════════════════" << std::endl;
    std::cout << "[QueryPlan] query=" << plan.query_name;
    if (sp.is_loaded) {
        std::cout << "   server=" << sp.hostname
                  << " (P=" << sp.physical_cores
                  << " H=" << sp.logical_cores
                  << " L3=" << static_cast<int>(l3_mb) << "MB)";
    }
    std::cout << std::endl;

    std::cout << "[QueryPlan] depth:     d_lb=" << plan.d_lb
              << "  mult_depth=" << plan.mult_depth
              << (plan.used_empirical_depth ? " (empirical)" : " (formula)")
              << std::endl;

    std::cout << "[QueryPlan] FHE:       ring_dim=" << plan.ring_dim
              << "  mult_depth=" << plan.mult_depth
              << "  L_eff=" << getLEff(plan.ring_dim, plan.mult_depth)
              << std::endl;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "[QueryPlan] CT:        ct=" << ct_mb << "MB"
              << "  ws_f=" << ws_f_mb << "MB"
              << "  ws_a=" << ws_a_mb << "MB"
              << std::endl;

    if (sp.is_loaded) {
        std::cout << "[QueryPlan] rho:       filter=" << plan.rho_filter
                  << " (" << rhoRegime(plan.rho_filter) << ")"
                  << "  agg=" << plan.rho_agg
                  << " (" << rhoRegime(plan.rho_agg) << ")"
                  << std::endl;
    }

    std::cout << "[QueryPlan] ════════════════════════════════════" << std::endl;
}

} // namespace vaultdb
