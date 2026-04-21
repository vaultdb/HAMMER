#include "operators/columnar/fhe_filter.h"

#include <query_table/columnar/fhe_column.h>
#include <query_table/columnar/fhe_column_chunk.h>
#include <util/system_configuration.h>
#include <util/crypto_manager/fhe_manager.h>
#include <util/fhe/fhe_comparator.h>
#include <util/dictionary_manager.h>
#include <util/utilities.h>
#include <util/google_test_flags.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cmath>
#include <numeric>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <string>
#include <cctype>
#include <omp.h>
#include <vector>
#include <atomic>
#include <iomanip>
#include <limits>
#include <mutex>
#include <set>
#include <util/fhe/fhe_perf_counter.h>
#include <util/fhe/fhe_query_plan.h>
#include <util/fhe/fhe_thread_cost_model.h>

namespace vaultdb {

namespace {
    using namespace lbcrypto;

    // ============================================================
    // Thread-local PlaintextCache for uniform-value packed plaintexts
    // ============================================================
    struct PtCacheKey {
        const void* cc;
        int64_t val;
        size_t slots;
        bool operator==(const PtCacheKey& o) const noexcept {
            return cc == o.cc && val == o.val && slots == o.slots;
        }
    };
    struct PtCacheKeyHash {
        size_t operator()(const PtCacheKey& k) const noexcept {
            size_t h = std::hash<const void*>{}(k.cc);
            h ^= std::hash<int64_t>{}(k.val) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<size_t>{}(k.slots) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
    thread_local std::unordered_map<PtCacheKey, Plaintext, PtCacheKeyHash> tl_pt_cache;

    inline Plaintext cachedUniformPt(const CryptoContext<DCRTPoly>& cc, int64_t val, size_t slots) {
        PtCacheKey key{cc.get(), val, slots};
        auto it = tl_pt_cache.find(key);
        if (it != tl_pt_cache.end()) return it->second;
        auto pt = cc->MakePackedPlaintext(std::vector<int64_t>(slots, val));
        tl_pt_cache.emplace(key, pt);
        return pt;
    }

    // Read physical core count from /proc/cpuinfo (unique physical_id+core_id pairs).
    static int readPhysicalCores() {
        std::ifstream f("/proc/cpuinfo");
        if (!f.is_open()) return 6;  // default
        std::set<std::string> cores;
        std::string line, phys_id, core_id;
        while (std::getline(f, line)) {
            if (line.rfind("physical id", 0) == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos) phys_id = line.substr(pos + 1);
            } else if (line.rfind("core id", 0) == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos) {
                    core_id = line.substr(pos + 1);
                    cores.insert(phys_id + ":" + core_id);
                }
            }
        }
        return cores.empty() ? 6 : static_cast<int>(cores.size());
    }

    // Read logical core count from /proc/cpuinfo (count of "processor" lines).
    static int readLogicalCores() {
        std::ifstream f("/proc/cpuinfo");
        if (!f.is_open()) return 12;  // default
        int count = 0;
        std::string line;
        while (std::getline(f, line))
            if (line.rfind("processor", 0) == 0) ++count;
        return count > 0 ? count : 12;
    }

    // Read L3 cache size from sysfs; falls back to 15 MB.
    static size_t readL3CacheSize() {
        for (int idx = 0; idx < 16; ++idx) {
            std::string base = "/sys/devices/system/cpu/cpu0/cache/index"
                               + std::to_string(idx);
            std::ifstream flevel(base + "/level");
            if (!flevel.is_open()) break;
            int level = 0;
            flevel >> level;
            if (level != 3) continue;
            std::ifstream fsize(base + "/size");
            if (!fsize.is_open()) break;
            std::string sz_str;
            fsize >> sz_str;                       // e.g. "15360K"
            size_t val = std::stoull(sz_str);      // numeric prefix
            if (sz_str.back() == 'K' || sz_str.back() == 'k') val *= 1024;
            else if (sz_str.back() == 'M' || sz_str.back() == 'm') val *= 1024 * 1024;
            return val;
        }
        return 15UL * 1024 * 1024;                 // 15 MB default
    }

    // Global stats for each style (reset per run)
    // NOTE: These are thread-safe only when used with critical sections in parallel regions
    static ComparisonStats poly_stats;
    static std::mutex poly_stats_mutex;

    // Phase A: enable detailed comparator stats (--cmp_stats). Off by default.
    static bool g_comparator_stats_enabled = false;

    // Set to true to use ternary sign polynomial (4 ct-ct mults/digit for base 4).
    // Set to false to use original dual-polynomial (5 ct-ct mults/digit for base 4).


    // ============================================================
    // Ternary Sign Polynomial Coefficients
    // T(z) = sum_{i=0}^{n-1} c_{2i+1} * z^{2i+1}
    // where n = B-1 for base B.
    // T(k) = 1 for k=1..B-1, T(0) = 0, T(p-k) = p-1 (= -1 mod p)
    // ============================================================

    struct TernaryCoeffs {
        uint64_t modulus;
        std::vector<int64_t> odd_coeffs;  // c1, c3, c5, ...
    };

    // Keyed by radix_base, each entry has 3 TernaryCoeffs (one per RNS modulus)
    static const std::unordered_map<size_t, std::array<TernaryCoeffs, 3>> ternary_coeffs_by_base = {
        {2, {{
            {1179649, {1}},
            {2752513, {1}},
            {8519681, {1}},
        }}},
        {3, {{
            {1179649, {983042, 196608}},
            {2752513, {2293762, 458752}},
            {8519681, {1419948, 7099734}},
        }}},
        {4, {{
            {1179649, {668469, 294912, 216269}},
            {2752513, {1009256, 688128, 1055130}},
            {8519681, {3691863, 2129920, 2697899}},
        }}},
        {5, {{
            {1179649, {794860, 352256, 199885, 1012298}},
            {2752513, {910952, 1739435, 1934405, 920235}},
            {8519681, {4604686, 6330596, 6366095, 8257667}},
        }}},
        {7, {{
            {1179649, {600635, 819437, 649831, 338601, 917391, 213053}},
            {2752513, {1024945, 550035, 2250275, 33346, 713349, 933077}},
            {8519681, {7040110, 5295481, 1474674, 7582502, 735447, 3430830}},
        }}},
        {9, {{
            {1179649, {339319, 558254, 195103, 569161, 195079, 223494, 1101601, 356937}},
            {2752513, {251872, 1932504, 93287, 771636, 945241, 44673, 2230032, 1988295}},
            {8519681, {7686888, 679978, 6536311, 5283866, 4296078, 8067457, 795370, 732777}},
        }}},
        {16, {{
            {1179649, {689308, 597705, 552685, 647403, 176592, 393727, 416176, 296538, 531462, 319714, 888879, 275965, 302752, 642004, 346985}},
            {2752513, {2551309, 501530, 1271975, 1327954, 1184602, 2312991, 2541283, 953796, 176116, 342972, 1869768, 1831847, 1906080, 793571, 2454311}},
            {8519681, {6079666, 386100, 5261429, 448158, 5998598, 5382204, 8203674, 8231227, 2790000, 4967020, 4348620, 5117486, 863672, 2741831, 7337764}},
        }}},
        {64, {{
            {1179649, {840012, 647000, 1156978, 51268, 354243, 951308, 388285, 16974, 76624, 1152179, 663225, 918429, 1114982, 276129, 980544, 1043668, 477686, 256896, 870184, 508799, 179587, 391297, 762285, 494417, 232000, 1006742, 333340, 1070200, 480790, 727546, 236315, 627501, 119626, 102932, 1116099, 895531, 439575, 903915, 415246, 223329, 68270, 944919, 1016421, 373175, 965603, 555371, 1027525, 620502, 630843, 183815, 51689, 535513, 698570, 316624, 383231, 222154, 734065, 976237, 134321, 999745, 163959, 248200, 35033}},
            {2752513, {331729, 471605, 302222, 963094, 2221886, 2543522, 1143883, 1290472, 59632, 129420, 2560944, 2317964, 217976, 2378986, 728778, 2676999, 1028743, 307731, 1229041, 143049, 2599222, 205495, 2513783, 810525, 2032910, 2583724, 421861, 778649, 504045, 579299, 479926, 1553046, 672075, 1723824, 2408468, 369377, 306497, 780957, 1616842, 673407, 2039958, 2586369, 1288275, 2294395, 573744, 2245007, 685236, 2492294, 2231460, 907304, 242184, 1066894, 141392, 2399578, 1184143, 541454, 1204801, 1347489, 688147, 323133, 1672675, 2406201, 2599137}},
            {8519681, {8271083, 1318579, 3494665, 6249128, 8040861, 2647150, 6211295, 8364793, 39921, 3476266, 5974997, 1438505, 6353181, 1159989, 49544, 5937280, 2644886, 2656050, 3983352, 7895775, 1243190, 8058908, 4429605, 8008566, 3880007, 4624504, 6435011, 699278, 3020383, 7051830, 5610342, 1862306, 3944776, 4861187, 3183240, 2734286, 4174277, 8499520, 1211131, 1091353, 1346989, 2709246, 4168569, 2211257, 7428432, 1946997, 4257504, 919326, 3733642, 8011843, 5232262, 5179128, 5039613, 2340579, 5098329, 1839467, 2924257, 7356548, 6274372, 2519450, 6467031, 6403656, 8390296}},
        }}},
    };

    // Modular inverse of 2 for each RNS modulus
    static const std::array<int64_t, 3> inv2_per_modulus = {
        589825,   // inv(2) mod 1179649
        1376257,  // inv(2) mod 2752513
        4259841,  // inv(2) mod 8519681
    };

    // Helper: get modulus index (0, 1, 2) from CryptoContext
    static size_t getModulusIndex(const CryptoContext<DCRTPoly>& cc) {
        uint64_t p = cc->GetCryptoParameters()->GetPlaintextModulus();
        if (p == 1179649) return 0;
        if (p == 2752513) return 1;
        if (p == 8519681) return 2;
        throw std::runtime_error("Unknown plaintext modulus for ternary coefficients: " + std::to_string(p));
    }

    void resetStats() {
        std::lock_guard<std::mutex> lock_poly(poly_stats_mutex);
        poly_stats = ComparisonStats{};
    }

    // Merges local_stats into global dst under mutex
    void accumulatePolyStats(ComparisonStats& dst, const ComparisonStats& src, std::mutex& mtx) {
        std::lock_guard<std::mutex> lock(mtx);
        dst.eval_mult_count += src.eval_mult_count;
        dst.eval_rotate_count += src.eval_rotate_count;
        dst.ciphertext_count += src.ciphertext_count;
        dst.relinearize_count += src.relinearize_count;
        dst.eval_add_count += src.eval_add_count;
        dst.eval_sub_count += src.eval_sub_count;
        dst.digit_compare_call_count += src.digit_compare_call_count;
        dst.poly_eval_gt_count += src.poly_eval_gt_count;
        dst.poly_eval_lt_count += src.poly_eval_lt_count;
    }

    struct ChannelOpStats {
        std::atomic<uint64_t> eval_add{0};
        std::atomic<uint64_t> eval_sub{0};
        std::atomic<uint64_t> eval_mult_ct_ct{0};
        std::atomic<uint64_t> eval_mult_ct_pt{0};
        std::atomic<uint64_t> eval_relinearize{0};
        std::atomic<uint64_t> eval_rotate{0};
        std::atomic<uint64_t> eval_modswitch{0};
        std::atomic<uint64_t> eval_keyswitch{0};
        std::atomic<uint64_t> eval_modreduce{0};  // explicit+implied

        inline void add() { eval_add.fetch_add(1, std::memory_order_relaxed); }
        inline void sub() { eval_sub.fetch_add(1, std::memory_order_relaxed); }
        inline void multCtCt() { eval_mult_ct_ct.fetch_add(1, std::memory_order_relaxed); }
        inline void multCtPt() { eval_mult_ct_pt.fetch_add(1, std::memory_order_relaxed); }
        inline void relin() { eval_relinearize.fetch_add(1, std::memory_order_relaxed); }
        inline void rotate() { eval_rotate.fetch_add(1, std::memory_order_relaxed); }
        inline void modswitch() { eval_modswitch.fetch_add(1, std::memory_order_relaxed); }
        inline void keyswitch() { eval_keyswitch.fetch_add(1, std::memory_order_relaxed); }
        inline void modreduce() { eval_modreduce.fetch_add(1, std::memory_order_relaxed); }
    };

    struct ChannelLatencyStats {
        std::atomic<uint64_t> chunk_count{0};
        std::atomic<uint64_t> sum_ns{0};
        std::atomic<uint64_t> max_ns{0};

        inline void record(uint64_t ns) {
            chunk_count.fetch_add(1, std::memory_order_relaxed);
            sum_ns.fetch_add(ns, std::memory_order_relaxed);
            uint64_t prev = max_ns.load(std::memory_order_relaxed);
            while (prev < ns && !max_ns.compare_exchange_weak(prev, ns, std::memory_order_relaxed)) {}
        }
    };

    void printChannelOpStats(const std::vector<ChannelOpStats>& stats, const char* label) {
        for (size_t ch = 0; ch < stats.size(); ++ch) {
            const auto& s = stats[ch];
            std::cout << "[OpStats " << (label ? label : "FheFilter") << "] ch=" << ch
                      << " EvalAdd=" << s.eval_add.load(std::memory_order_relaxed)
                      << " EvalSub=" << s.eval_sub.load(std::memory_order_relaxed)
                      << " EvalMult(ct*ct)=" << s.eval_mult_ct_ct.load(std::memory_order_relaxed)
                      << " EvalMult(ct*pt)=" << s.eval_mult_ct_pt.load(std::memory_order_relaxed)
                      << " Relinearize=" << s.eval_relinearize.load(std::memory_order_relaxed)
                      << " Rotate=" << s.eval_rotate.load(std::memory_order_relaxed)
                      << " ModSwitch(explicit)=" << s.eval_modswitch.load(std::memory_order_relaxed)
                      << " KeySwitch(explicit+implied)=" << s.eval_keyswitch.load(std::memory_order_relaxed)
                      << " ModReduce(explicit+implied)=" << s.eval_modreduce.load(std::memory_order_relaxed)
                      << std::endl;
        }
    }

    size_t getTowerCount(const CryptoContext<DCRTPoly>& cc) {
        if (!cc || !cc->GetCryptoParameters() || !cc->GetCryptoParameters()->GetElementParams()) return 0;
        return cc->GetCryptoParameters()->GetElementParams()->GetParams().size();
    }


    int64_t baseRelativeEpochDays() {
        static const int64_t base_days = []() {
            std::tm timeinfo{};
            timeinfo.tm_year = 1992 - 1900;
            timeinfo.tm_mon = 1 - 1;
            timeinfo.tm_mday = 3;
            timeinfo.tm_hour = 0;
            timeinfo.tm_min = 0;
            timeinfo.tm_sec = 0;
            timeinfo.tm_isdst = -1;
            time_t epoch_seconds = mktime(&timeinfo);
            return static_cast<int64_t>(epoch_seconds / (24 * 3600));
        }();
        return base_days;
    }

    int64_t extractIntValue(const PlainField& field, const std::string& table_name = "", const std::string& column_name = "") {
        switch (field.getType()) {
            case FieldType::INT:
                return static_cast<int64_t>(field.getValue<int32_t>());
            case FieldType::LONG:
            case FieldType::DATE:
                return field.getValue<int64_t>();
            case FieldType::BOOL:
                return field.getValue<bool>() ? 1 : 0;
            case FieldType::FLOAT: {
                // Decimal predicates are represented as scaled integers in dictionary metadata.
                int scale = 1;
                if (!table_name.empty() && !column_name.empty()) {
                    scale = DictionaryManager::getInstance().getScaleFactor(table_name, column_name);
                    if (scale <= 0) scale = 1;
                }
                const double v = static_cast<double>(field.getValue<float_t>());
                return static_cast<int64_t>(std::llround(v * static_cast<double>(scale)));
            }
            case FieldType::STRING: {
                std::string str = field.getString();
                auto trim = [](std::string& s) {
                    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
                    size_t i = 0;
                    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
                    if (i > 0) s.erase(0, i);
                };
                trim(str);
                auto& dm = DictionaryManager::getInstance();
                std::string table = table_name;
                if (table.empty() && !column_name.empty()) {
                    table = dm.getTableForColumn(column_name);
                }
                if (str.empty()) {
                    // Fixed-width CHAR padding / dummy rows can appear as blanks.
                    return 0;
                }
                if (!table.empty() && !column_name.empty()) {
                    return static_cast<int64_t>(dm.lookupId(table, column_name, str));
                }
                // Fallback for non-dictionary string columns.
                return str.empty() ? 0 : static_cast<int64_t>(static_cast<unsigned char>(str[0]));
            }
            default:
                throw std::runtime_error("FheFilter: unsupported field type for comparison column");
        }
    }

    std::vector<int64_t> encodeRadix(int64_t value, size_t base, size_t digits) {
        std::vector<int64_t> encoded(digits, 0);
        int64_t current = value;
        for (size_t i = 0; i < digits; ++i) {
            encoded[i] = current % static_cast<int64_t>(base);
            current /= static_cast<int64_t>(base);
        }
        return encoded;
    }

    // Build radix digit columns from packed slot values
    std::vector<std::vector<int64_t>> buildRadixColumns(const std::vector<int64_t>& values,
                                                        size_t base,
                                                        size_t digits,
                                                        size_t pack_slots) {
        std::vector<std::vector<int64_t>> columns(digits);
        for (auto& column : columns) {
            column.resize(pack_slots, 0);
        }
        for (size_t slot = 0; slot < pack_slots; ++slot) {
            int64_t current = (slot < values.size()) ? values[slot] : 0;
            for (size_t i = 0; i < digits; ++i) {
                columns[i][slot] = current % static_cast<int64_t>(base);
                current /= static_cast<int64_t>(base);
            }
        }
        return columns;
    }

    /**
     * Result structure for atomic comparator
     * Contains GT (Greater Than), LT (Less Than), and EQ (Equal) indicators
     */
    struct ComparatorResult {
        Ciphertext<DCRTPoly> GT;  // 1 if A > B, 0 otherwise
        Ciphertext<DCRTPoly> LT;  // 1 if A < B, 0 otherwise
        Ciphertext<DCRTPoly> EQ;  // 1 if A = B, 0 otherwise
    };
    
    /**
     * Ternary Sign Polynomial comparator.
     *
     * Evaluates a single odd polynomial T(z) that maps:
     *   z > 0 (mod p) → T = +1
     *   z = 0         → T = 0
     *   z < 0 (mod p) → T = -1 (= p-1)
     *
     * Then extracts GT, LT, EQ via:
     *   GT = (T + T²) · inv(2) mod p
     *   LT = (T² - T) · inv(2) mod p
     *   EQ = 1 - T²
     *
     * Cost: 4 ct-ct mults + relins for base 4
     */
    ComparatorResult AtomicComparatorTernary(
            const Ciphertext<DCRTPoly>& diff_cipher,
            const CryptoContext<DCRTPoly>& cc,
            const PublicKey<DCRTPoly>& pk,
            size_t pack_slots,
            size_t radix_base,
            ComparisonStats* stats = nullptr) {

        if (stats && g_comparator_stats_enabled) stats->digit_compare_call_count++;

        size_t mod_idx = getModulusIndex(cc);
        int64_t inv2 = inv2_per_modulus[mod_idx];

        auto it = ternary_coeffs_by_base.find(radix_base);
        if (it == ternary_coeffs_by_base.end()) {
            throw std::runtime_error(
                "AtomicComparatorTernary: no ternary coefficients for radix_base=" +
                std::to_string(radix_base));
        }
        const auto& coeffs = it->second[mod_idx].odd_coeffs;
        size_t n_coeffs = coeffs.size();  // = radix_base - 1

        // ---- Phase A: Build odd power basis {z, z³, z⁵, ...} ----
        // Strategy: z → z² → z³=z²·z → z⁵=z³·z² → z⁷=z⁵·z² → ...
        Ciphertext<DCRTPoly> z = diff_cipher;
        std::vector<Ciphertext<DCRTPoly>> odd_powers(n_coeffs);
        odd_powers[0] = z;  // z^1

        if (n_coeffs >= 2) {
            // z² = z · z
            auto z_sq = cc->EvalMultAndRelinearize(z, z);
            if (stats && g_comparator_stats_enabled) {
                stats->eval_mult_count++;
                stats->relinearize_count++;
            }

            // z³ = z² · z
            odd_powers[1] = cc->EvalMultAndRelinearize(z_sq, z);
            if (stats && g_comparator_stats_enabled) {
                stats->eval_mult_count++;
                stats->relinearize_count++;
            }

            // Higher odd powers: z⁵ = z³·z², z⁷ = z⁵·z², ...
            for (size_t k = 2; k < n_coeffs; ++k) {
                odd_powers[k] = cc->EvalMultAndRelinearize(odd_powers[k - 1], z_sq);
                if (stats && g_comparator_stats_enabled) {
                    stats->eval_mult_count++;
                    stats->relinearize_count++;
                }
            }
        }

        // ---- Phase B: T = Σ coeffs[i] · z^(2i+1) (all ct-pt mults, zero depth) ----
        Ciphertext<DCRTPoly> T;
        bool first_term = true;
        for (size_t i = 0; i < n_coeffs; ++i) {
            Plaintext coeff_pt = cachedUniformPt(cc, coeffs[i], pack_slots);
            auto term = cc->EvalMult(odd_powers[i], coeff_pt);

            if (first_term) {
                T = term;
                first_term = false;
            } else {
                T = cc->EvalAdd(T, term);
                if (stats && g_comparator_stats_enabled) stats->eval_add_count++;
            }
        }

        // ---- Phase C: T² = T · T  (1 ct-ct mult) ----
        auto T_sq = cc->EvalMultAndRelinearize(T, T);
        if (stats && g_comparator_stats_enabled) {
            stats->eval_mult_count++;
            stats->relinearize_count++;
        }

        // ---- Phase D: Extract GT, LT, EQ (all ct-pt, zero ct-ct) ----
        // GT = (T + T²) · inv(2) mod p
        auto T_plus_Tsq = cc->EvalAdd(T, T_sq);
        if (stats && g_comparator_stats_enabled) stats->eval_add_count++;

        Plaintext inv2_pt = cachedUniformPt(cc, inv2, pack_slots);
        auto GT = cc->EvalMult(T_plus_Tsq, inv2_pt);

        // LT = (T² - T) · inv(2) mod p
        auto Tsq_minus_T = cc->EvalSub(T_sq, T);
        if (stats && g_comparator_stats_enabled) stats->eval_sub_count++;
        auto LT = cc->EvalMult(Tsq_minus_T, inv2_pt);

        // EQ = 1 - T²
        std::vector<int64_t> ones_vec(pack_slots, 1);
        Plaintext ones_plain = cc->MakePackedPlaintext(ones_vec);
        auto EQ = cc->EvalSub(ones_plain, T_sq);
        if (stats && g_comparator_stats_enabled) stats->eval_sub_count++;

        if (stats && g_comparator_stats_enabled) stats->ciphertext_count += 3;

        return {GT, LT, EQ};
    }

    struct LexMergeNode {
        Ciphertext<DCRTPoly> primary;
        Ciphertext<DCRTPoly> eq;
    };

    Ciphertext<DCRTPoly> reduceLexicographicalTree(const CryptoContext<DCRTPoly>& cc,
                                                   const std::vector<Ciphertext<DCRTPoly>>& primary_digits,
                                                   const std::vector<Ciphertext<DCRTPoly>>& eq_digits,
                                                   ComparisonStats& local_stats) {
        if (primary_digits.empty() || primary_digits.size() != eq_digits.size()) {
            throw std::runtime_error("reduceLexicographicalTree: invalid digit vectors");
        }
        if (primary_digits.size() == 1) return primary_digits[0];

        std::vector<LexMergeNode> current(primary_digits.size());
        for (size_t i = 0; i < primary_digits.size(); ++i) {
            current[i] = {primary_digits[i], eq_digits[i]};
        }

        // Parallel tree reduction at each level
        while (current.size() > 1) {
            size_t half = current.size() / 2;
            std::vector<LexMergeNode> merged_pairs(half);
            #pragma omp parallel for schedule(static) if(half >= 4)
            for (size_t i = 0; i < half; ++i) {
                auto& lower = current[2 * i];
                auto& higher = current[2 * i + 1];
                auto eq_times_primary = cc->EvalMultAndRelinearize(higher.eq, lower.primary);
                auto merged_primary = cc->EvalAdd(higher.primary, eq_times_primary);
                auto merged_eq = cc->EvalMultAndRelinearize(higher.eq, lower.eq);
                merged_pairs[i] = {merged_primary, merged_eq};
            }
            if (g_comparator_stats_enabled) {
                local_stats.eval_mult_count += half * 2;
                local_stats.relinearize_count += half * 2;
                local_stats.eval_add_count += half;
            }
            local_stats.ciphertext_count += half * 3;
            std::vector<LexMergeNode> next;
            next.reserve(half + (current.size() % 2));
            for (size_t i = 0; i < half; ++i) next.push_back(std::move(merged_pairs[i]));
            if (current.size() % 2 == 1) next.push_back(current.back());
            current = std::move(next);
        }
        return current[0].primary;
    }

    Ciphertext<DCRTPoly> reduceEqProductTree(const CryptoContext<DCRTPoly>& cc,
                                             const std::vector<Ciphertext<DCRTPoly>>& eq_digits,
                                             ComparisonStats& local_stats) {
        if (eq_digits.empty()) {
            throw std::runtime_error("reduceEqProductTree: empty eq vector");
        }
        if (eq_digits.size() == 1) return eq_digits[0];

        std::vector<Ciphertext<DCRTPoly>> current = eq_digits;
        // Parallel tree reduction at each level
        while (current.size() > 1) {
            size_t half = current.size() / 2;
            std::vector<Ciphertext<DCRTPoly>> merged(half);
            #pragma omp parallel for schedule(static) if(half >= 4)
            for (size_t i = 0; i < half; ++i) {
                merged[i] = cc->EvalMultAndRelinearize(current[2 * i], current[2 * i + 1]);
            }
            if (g_comparator_stats_enabled) {
                local_stats.eval_mult_count += half;
                local_stats.relinearize_count += half;
            }
            local_stats.ciphertext_count += half;
            std::vector<Ciphertext<DCRTPoly>> next;
            next.reserve(half + (current.size() % 2));
            for (size_t i = 0; i < half; ++i) next.push_back(std::move(merged[i]));
            if (current.size() % 2 == 1) next.push_back(current.back());
            current = std::move(next);
        }
        return current[0];
    }

    /**
     * Build diff_i = data_digit[i] - threshold_digit[i].
     * CT-PT path (default): data digit is plaintext → EvalSub(pt, ct)
     * CT-CT path (all_column_encrypt): data digit encrypted first → EvalSub(ct, ct)
     */
    inline Ciphertext<DCRTPoly> buildDigitDiff(
            const CryptoContext<DCRTPoly>& cc,
            const PublicKey<DCRTPoly>& pk,
            const std::vector<int64_t>& radix_digit_values,
            const Ciphertext<DCRTPoly>& threshold_digit_cipher) {
        Plaintext plain = cc->MakePackedPlaintext(radix_digit_values);
        if (FLAGS_all_column_encrypt) {
            // CT-CT: encrypt the data digit, then subtract
            auto enc_digit = cc->Encrypt(pk, plain);
            return cc->EvalSub(enc_digit, threshold_digit_cipher);
        } else {
            // CT-PT: subtract plaintext from ciphertext directly
            return cc->EvalSub(plain, threshold_digit_cipher);
        }
    }

    /**
     * Helper function to compute GT(A, B) lexicographically.
     * Returns GT result without negation.
     *
     * Algorithm:
     * 1. For each digit i (LSB to MSB):
     *    - Compute GT_i = GT(A_i, B_i) using AtomicComparator
     *    - Compute EQ_i from AtomicComparator
     *
     * 2. Combine using lexicographical formula:
     *    result = GT[0] + EQ[0] * (GT[1] + EQ[1] * (GT[2] + ...))
     *    Returns 1 if A > B, 0 otherwise
     */
    Ciphertext<DCRTPoly> polynomialComparisonGtInternal(const CryptoContext<DCRTPoly>& cc,
                                                        const PublicKey<DCRTPoly>& pk,
                                                        const std::vector<Ciphertext<DCRTPoly>>& threshold_digit_ciphers,
                                                        const std::vector<std::vector<int64_t>>& radix_columns,
                                                        size_t pack_slots,
                                                        size_t radix_base,
                                                        ComparisonStats& local_stats) {
        int num_digits = static_cast<int>(threshold_digit_ciphers.size());
        std::vector<Ciphertext<DCRTPoly>> gt_digits(num_digits);
        std::vector<Ciphertext<DCRTPoly>> eq_digits(num_digits);
        local_stats.ciphertext_count += num_digits * 2;

        // Parallel digit comparison loop
        {
            const int max_par = omp_get_max_threads();
            std::vector<ComparisonStats> tl_stats(max_par);
            #pragma omp parallel for schedule(static) if(num_digits >= 2)
            for (int i = 0; i < num_digits; ++i) {
                int tid = omp_get_thread_num();
                Ciphertext<DCRTPoly> diff_i = buildDigitDiff(cc, pk, radix_columns[i], threshold_digit_ciphers[i]);
                if (g_comparator_stats_enabled) tl_stats[tid].eval_sub_count++;
                tl_stats[tid].ciphertext_count++;

                ComparatorResult result = AtomicComparatorTernary(diff_i, cc, pk, pack_slots, radix_base, &tl_stats[tid]);
                gt_digits[i] = result.GT;
                eq_digits[i] = result.EQ;

                tl_stats[tid].ciphertext_count += 3;
            }
            for (auto& s : tl_stats) {
                local_stats.eval_mult_count += s.eval_mult_count;
                local_stats.eval_rotate_count += s.eval_rotate_count;
                local_stats.ciphertext_count += s.ciphertext_count;
                local_stats.relinearize_count += s.relinearize_count;
                local_stats.eval_add_count += s.eval_add_count;
                local_stats.eval_sub_count += s.eval_sub_count;
                local_stats.digit_compare_call_count += s.digit_compare_call_count;
                local_stats.poly_eval_gt_count += s.poly_eval_gt_count;
                local_stats.poly_eval_lt_count += s.poly_eval_lt_count;
            }
        }

        // [Phase 2] Tree-based lexicographical merge (O(log n) depth)
        return reduceLexicographicalTree(cc, gt_digits, eq_digits, local_stats);
    }

    /**
     * Helper function to compute LT(A, B) lexicographically.
     * Returns LT result without negation.
     */
    Ciphertext<DCRTPoly> polynomialComparisonLtInternal(const CryptoContext<DCRTPoly>& cc,
                                                const PublicKey<DCRTPoly>& pk,
                                                const std::vector<Ciphertext<DCRTPoly>>& threshold_digit_ciphers,
                                                const std::vector<std::vector<int64_t>>& radix_columns,
                                                        size_t pack_slots,
                                                        size_t radix_base,
                                                        ComparisonStats& local_stats) {
        int num_digits = static_cast<int>(threshold_digit_ciphers.size());
        std::vector<Ciphertext<DCRTPoly>> lt_digits(num_digits);
        std::vector<Ciphertext<DCRTPoly>> eq_digits(num_digits);
        local_stats.ciphertext_count += num_digits * 2;

        // Parallel digit comparison loop
        {
            const int max_par = omp_get_max_threads();
            std::vector<ComparisonStats> tl_stats(max_par);
            #pragma omp parallel for schedule(static) if(num_digits >= 2)
            for (int i = 0; i < num_digits; ++i) {
                int tid = omp_get_thread_num();
                Ciphertext<DCRTPoly> diff_i = buildDigitDiff(cc, pk, radix_columns[i], threshold_digit_ciphers[i]);
                if (g_comparator_stats_enabled) tl_stats[tid].eval_sub_count++;
                tl_stats[tid].ciphertext_count++;

                ComparatorResult result = AtomicComparatorTernary(diff_i, cc, pk, pack_slots, radix_base, &tl_stats[tid]);
                lt_digits[i] = result.LT;
                eq_digits[i] = result.EQ;

                tl_stats[tid].ciphertext_count += 3;
            }
            for (auto& s : tl_stats) {
                local_stats.eval_mult_count += s.eval_mult_count;
                local_stats.eval_rotate_count += s.eval_rotate_count;
                local_stats.ciphertext_count += s.ciphertext_count;
                local_stats.relinearize_count += s.relinearize_count;
                local_stats.eval_add_count += s.eval_add_count;
                local_stats.eval_sub_count += s.eval_sub_count;
                local_stats.digit_compare_call_count += s.digit_compare_call_count;
                local_stats.poly_eval_gt_count += s.poly_eval_gt_count;
                local_stats.poly_eval_lt_count += s.poly_eval_lt_count;
            }
        }

        // [Phase 2] Tree-based lexicographical merge (O(log n) depth)
        return reduceLexicographicalTree(cc, lt_digits, eq_digits, local_stats);
    }

    /**
     * Polynomial-style lexicographical comparison for A <= B.
     * Returns 1 if A <= B, 0 otherwise
     */
    Ciphertext<DCRTPoly> polynomialComparisonLe(const CryptoContext<DCRTPoly>& cc,
                                                const PublicKey<DCRTPoly>& pk,
                                                const std::vector<Ciphertext<DCRTPoly>>& threshold_digit_ciphers,
                                                const std::vector<std::vector<int64_t>>& radix_columns,
                                                size_t pack_slots,
                                                size_t radix_base) {
        ComparisonStats local_stats;
        Ciphertext<DCRTPoly> gt_result = polynomialComparisonGtInternal(cc, pk, threshold_digit_ciphers, radix_columns, pack_slots, radix_base, local_stats);

        // Convert GT to LE: LE(A, B) = 1 - GT(A, B)
        auto ones_le = cachedUniformPt(cc, 1, pack_slots);
        Ciphertext<DCRTPoly> result = cc->EvalSub(ones_le, gt_result);
        if (g_comparator_stats_enabled) local_stats.eval_sub_count++;
        local_stats.ciphertext_count++; // final result

        accumulatePolyStats(poly_stats, local_stats, poly_stats_mutex);

        return result;
    }

    /**
     * Polynomial-style lexicographical comparison for A > B.
     * Returns 1 if A > B, 0 otherwise
     * Optimized to avoid double negation by directly computing GT.
     */
    Ciphertext<DCRTPoly> polynomialComparisonGt(const CryptoContext<DCRTPoly>& cc,
                                                const PublicKey<DCRTPoly>& pk,
                                                const std::vector<Ciphertext<DCRTPoly>>& threshold_digit_ciphers,
                                                const std::vector<std::vector<int64_t>>& radix_columns,
                                                size_t pack_slots,
                                                size_t radix_base) {
        ComparisonStats local_stats;
        Ciphertext<DCRTPoly> result = polynomialComparisonGtInternal(cc, pk, threshold_digit_ciphers, radix_columns, pack_slots, radix_base, local_stats);
        
        accumulatePolyStats(poly_stats, local_stats, poly_stats_mutex);

        return result;
    }

    /**
     * Polynomial-style lexicographical comparison for A >= B.
     * 
     * This is computed as: GE(A, B) = NOT(LT(A, B))
     * Where LT(A, B) is computed by getting the LT result from AtomicComparator
     * (which computes P(-z) where z = A - B, giving 1 if A < B)
     * 
     * Algorithm:
     * 1. For each digit i (LSB to MSB):
     *    - Compute LT_i = LT(A_i, B_i) using AtomicComparator
     *    - Compute EQ_i from AtomicComparator
     * 
     * 2. Combine using lexicographical formula for LT:
     *    LT_result = LT[0] + EQ[0] * (LT[1] + EQ[1] * (LT[2] + ...))
     * 
     * 3. Convert LT to GE: GE(A, B) = 1 - LT(A, B)
     */
    Ciphertext<DCRTPoly> polynomialComparisonGe(const CryptoContext<DCRTPoly>& cc,
                                                const PublicKey<DCRTPoly>& pk,
                                                const std::vector<Ciphertext<DCRTPoly>>& threshold_digit_ciphers,
                                                const std::vector<std::vector<int64_t>>& radix_columns,
                                                size_t pack_slots,
                                                size_t radix_base) {
        ComparisonStats local_stats;

        int num_digits = static_cast<int>(threshold_digit_ciphers.size());
        std::vector<Ciphertext<DCRTPoly>> lt_digits(num_digits);
        std::vector<Ciphertext<DCRTPoly>> eq_digits(num_digits);
        local_stats.ciphertext_count += num_digits * 2;

        // Parallel digit comparison loop
        {
            const int max_par = omp_get_max_threads();
            std::vector<ComparisonStats> tl_stats(max_par);
            #pragma omp parallel for schedule(static) if(num_digits >= 2)
            for (int i = 0; i < num_digits; ++i) {
                int tid = omp_get_thread_num();
                Ciphertext<DCRTPoly> diff_i = buildDigitDiff(cc, pk, radix_columns[i], threshold_digit_ciphers[i]);
                if (g_comparator_stats_enabled) tl_stats[tid].eval_sub_count++;
                tl_stats[tid].ciphertext_count++;

                ComparatorResult result = AtomicComparatorTernary(diff_i, cc, pk, pack_slots, radix_base, &tl_stats[tid]);
                lt_digits[i] = result.LT;
                eq_digits[i] = result.EQ;

                tl_stats[tid].ciphertext_count += 3;
            }
            for (auto& s : tl_stats) {
                local_stats.eval_mult_count += s.eval_mult_count;
                local_stats.eval_rotate_count += s.eval_rotate_count;
                local_stats.ciphertext_count += s.ciphertext_count;
                local_stats.relinearize_count += s.relinearize_count;
                local_stats.eval_add_count += s.eval_add_count;
                local_stats.eval_sub_count += s.eval_sub_count;
                local_stats.digit_compare_call_count += s.digit_compare_call_count;
                local_stats.poly_eval_gt_count += s.poly_eval_gt_count;
                local_stats.poly_eval_lt_count += s.poly_eval_lt_count;
            }
        }

        // [Phase 2] Tree-based LT merge (O(log n) depth)
        Ciphertext<DCRTPoly> result_lt = reduceLexicographicalTree(cc, lt_digits, eq_digits, local_stats);

        // Final Inversion: GE = 1 - LT
        auto ones_ge = cachedUniformPt(cc, 1, pack_slots);
        Ciphertext<DCRTPoly> result = cc->EvalSub(ones_ge, result_lt);
        if (g_comparator_stats_enabled) local_stats.eval_sub_count++;

        accumulatePolyStats(poly_stats, local_stats, poly_stats_mutex);

        return result;
    }

    /**
     * Polynomial-style equality comparison: A = B.
     * Result = EQ[0] * EQ[1] * ... * EQ[n-1] (all digits must match).
     */
    Ciphertext<DCRTPoly> polynomialComparisonEqual(const CryptoContext<DCRTPoly>& cc,
                                                   const PublicKey<DCRTPoly>& pk,
                                                   const std::vector<Ciphertext<DCRTPoly>>& threshold_digit_ciphers,
                                                   const std::vector<std::vector<int64_t>>& radix_columns,
                                                   size_t pack_slots,
                                                   size_t radix_base) {
        ComparisonStats local_stats;
        int num_digits = static_cast<int>(threshold_digit_ciphers.size());
        std::vector<Ciphertext<DCRTPoly>> eq_digits(num_digits);

        // Parallel digit comparison loop
        {
            const int max_par = omp_get_max_threads();
            std::vector<ComparisonStats> tl_stats(max_par);
            #pragma omp parallel for schedule(static) if(num_digits >= 2)
            for (int i = 0; i < num_digits; ++i) {
                int tid = omp_get_thread_num();
                Ciphertext<DCRTPoly> diff_i = buildDigitDiff(cc, pk, radix_columns[i], threshold_digit_ciphers[i]);
                if (g_comparator_stats_enabled) tl_stats[tid].eval_sub_count++;
                tl_stats[tid].ciphertext_count++;

                ComparatorResult result = AtomicComparatorTernary(diff_i, cc, pk, pack_slots, radix_base, &tl_stats[tid]);
                eq_digits[i] = result.EQ;
                tl_stats[tid].ciphertext_count += 3;
            }
            for (auto& s : tl_stats) {
                local_stats.eval_mult_count += s.eval_mult_count;
                local_stats.eval_rotate_count += s.eval_rotate_count;
                local_stats.ciphertext_count += s.ciphertext_count;
                local_stats.relinearize_count += s.relinearize_count;
                local_stats.eval_add_count += s.eval_add_count;
                local_stats.eval_sub_count += s.eval_sub_count;
                local_stats.digit_compare_call_count += s.digit_compare_call_count;
                local_stats.poly_eval_gt_count += s.poly_eval_gt_count;
                local_stats.poly_eval_lt_count += s.poly_eval_lt_count;
            }
        }

        // EQ chain: tree-based product (O(log n) depth)
        Ciphertext<DCRTPoly> result_eq = reduceEqProductTree(cc, eq_digits, local_stats);

        accumulatePolyStats(poly_stats, local_stats, poly_stats_mutex);
        return result_eq;
    }

}

namespace {
    int64_t extractColumnValue(const PlainColumn& column, size_t row_idx,
                               const std::string& table_name = "",
                               const std::string& column_name = "") {
        size_t cumulative = 0;
        for (const auto& chunk : column.getPlainChunks()) {
            if (!chunk) {
                continue;
            }
            const auto& values = chunk->getValues();
            if (row_idx < cumulative + values.size()) {
                return extractIntValue(values[row_idx - cumulative], table_name, column_name);
            }
            cumulative += values.size();
        }
        throw std::out_of_range("extractColumnValue: row index out of range");
    }

    /**
     * Batch extraction: fill out[0..count-1] with column values at [start_idx, start_idx+count).
     * O(chunks) to find start + O(count) to fill; avoids O(count * chunks) from repeated scans.
     */
    void extractColumnValuesBatch(const PlainColumn& column, size_t start_idx, size_t count,
                                  int64_t* out, int64_t pad_value = 0,
                                  const std::string& table_name = "",
                                  const std::string& column_name = "") {
        const auto& chunks = column.getPlainChunks();
        if (chunks.empty()) {
            for (size_t i = 0; i < count; ++i) out[i] = pad_value;
            return;
        }
        size_t cumulative = 0;
        size_t chunk_id = 0;
        size_t offset_in_chunk = 0;
        for (; chunk_id < chunks.size(); ++chunk_id) {
            const auto& ch = chunks[chunk_id];
            if (!ch) continue;
            size_t ch_size = ch->getValues().size();
            if (start_idx < cumulative + ch_size) {
                offset_in_chunk = start_idx - cumulative;
                break;
            }
            cumulative += ch_size;
        }
        if (chunk_id >= chunks.size()) {
            for (size_t i = 0; i < count; ++i) out[i] = pad_value;
            return;
        }
        size_t filled = 0;
        while (filled < count && chunk_id < chunks.size()) {
            const auto& ch = chunks[chunk_id];
            if (!ch) { ++chunk_id; continue; }
            const auto& values = ch->getValues();
            size_t ch_size = values.size();
            size_t avail = ch_size - offset_in_chunk;
            size_t to_take = std::min(count - filled, avail);
            for (size_t k = 0; k < to_take; ++k) {
                out[filled + k] = extractIntValue(values[offset_in_chunk + k], table_name, column_name);
            }
            filled += to_take;
            offset_in_chunk = 0;
            ++chunk_id;
        }
        for (; filled < count; ++filled) out[filled] = pad_value;
    }

    // Generic comparison node supporting all comparison types
    // - LE (<=): polynomialComparisonLe
    // - LT (<):  1 - GE = 1 - polynomialComparisonGe (or NOT(GE))
    // - GE (>=): swap operands in LE, i.e., B <= A
    // - GT (>):  1 - LE = NOT(LE)
    static constexpr size_t kUseComparisonContext = static_cast<size_t>(-1);

    class BFVRadixComparisonNode : public SIMDExpressionNode<FheColumnChunk> {
    public:
        BFVRadixComparisonNode(QueryFieldDesc field_desc,
                              std::string column_name,
                              std::vector<Ciphertext<DCRTPoly>> threshold_digit_ciphers,
                              FheFilterStyle style,
                              size_t radix_base,
                              size_t num_digits,
                              size_t rns_channel = kUseComparisonContext)
            : field_desc_(std::move(field_desc)),
              column_name_(std::move(column_name)),
              threshold_digit_ciphers_(std::move(threshold_digit_ciphers)),
              style_(style),
              radix_base_(radix_base),
              num_digits_(num_digits),
              rns_channel_(rns_channel) {
            FheManager& manager = FheManager::getInstance();
            q_params_.simdSlots = static_cast<unsigned int>(manager.getBFVComparisonBatchSize());
            type_desc_ = FheTypeDescriptor(FheDataType::BOOLEAN, FheEncodingType::BFV_PACKED_ENCODING);
        }

        BFVRadixComparisonNode(const BFVRadixComparisonNode& src)
            : field_desc_(src.field_desc_),
              column_name_(src.column_name_),
              threshold_digit_ciphers_(src.threshold_digit_ciphers_),
              style_(src.style_),
              radix_base_(src.radix_base_),
              num_digits_(src.num_digits_),
              rns_channel_(src.rns_channel_),
              q_params_(src.q_params_),
              type_desc_(src.type_desc_)
              // radix_cache_ and radix_cache_mutex_ start fresh
        {}

        std::shared_ptr<FheColumnChunk> call(const ColumnTableBase<void>* table, size_t chunk_idx) const override {
            const auto* fhe_table = dynamic_cast<const FheColumnTable*>(table);
            if (!fhe_table) {
                throw std::runtime_error("BFVRadixComparisonNode: table is not FheColumnTable");
            }

            auto plain_snapshot = fhe_table->getPlainSnapshot();
            if (!plain_snapshot) {
                throw std::runtime_error("BFVRadixComparisonNode: missing plain snapshot");
            }
            auto column = plain_snapshot->getPlainColumn(column_name_);
            if (!column) {
                throw std::runtime_error("BFVRadixComparisonNode: column '" + column_name_ + "' not found");
            }

            FheManager& manager = FheManager::getInstance();
            size_t pack_slots = manager.getBFVComparisonBatchSize();
            size_t row_count = plain_snapshot->getRowCount();
            size_t start_idx = chunk_idx * pack_slots;
            if (start_idx >= row_count) {
                return std::make_shared<FheColumnChunk>();
            }
            size_t effective_count = std::min(pack_slots, row_count - start_idx);

            std::vector<int64_t> chunk_values(pack_slots, 0);
            extractColumnValuesBatch(*column, start_idx, pack_slots, chunk_values.data(), 0,
                                     field_desc_.getTableName(), column_name_);

            if (FLAGS_debug && chunk_idx == 0) {
                int64_t min_v = std::numeric_limits<int64_t>::max();
                int64_t max_v = std::numeric_limits<int64_t>::min();
                for (size_t i = 0; i < effective_count; ++i) {
                    min_v = std::min(min_v, chunk_values[i]);
                    max_v = std::max(max_v, chunk_values[i]);
                }
                auto styleToString = [&](FheFilterStyle s) -> const char* {
                    switch (s) {
                        case FheFilterStyle::PolynomialLE: return "PolynomialLE";
                        case FheFilterStyle::PolynomialGT: return "PolynomialGT";
                        case FheFilterStyle::PolynomialGE: return "PolynomialGE";
                        case FheFilterStyle::PolynomialLT: return "PolynomialLT";
                        case FheFilterStyle::PolynomialEQ: return "PolynomialEQ";
                        default: return "Unknown";
                    }
                };
                std::cout << "[FheFilter][Debug] predicate=" << styleToString(style_)
                          << " column=" << column_name_
                          << " table=" << field_desc_.getTableName()
                          << " chunk_idx=" << chunk_idx
                          << " effective_count=" << effective_count
                          << " radix_base=" << radix_base_
                          << " num_digits=" << num_digits_
                          << " rns_channel=" << (rns_channel_ == kUseComparisonContext ? -1 : static_cast<int>(rns_channel_))
                          << " min=" << (effective_count == 0 ? 0 : min_v)
                          << " max=" << (effective_count == 0 ? 0 : max_v)
                          << " first_values=[";
                for (size_t i = 0; i < std::min<size_t>(8, effective_count); ++i) {
                    if (i > 0) std::cout << ",";
                    std::cout << chunk_values[i];
                }
                std::cout << "]" << std::endl;
            }

            // Cache radix columns per chunk_idx
            std::vector<std::vector<int64_t>> radix_columns;
            {
                std::lock_guard<std::mutex> lk(radix_cache_mutex_);
                auto it = radix_cache_.find(chunk_idx);
                if (it != radix_cache_.end()) {
                    radix_columns = it->second;
                } else {
                    radix_columns = buildRadixColumns(chunk_values, radix_base_, num_digits_, pack_slots);
                    radix_cache_.emplace(chunk_idx, radix_columns);
                }
            }

            CryptoContext<DCRTPoly> cc;
            PublicKey<DCRTPoly> pk;
            if (rns_channel_ != kUseComparisonContext && rns_channel_ < manager.getRnsCount()) {
                cc = manager.getRnsContext(rns_channel_);
                pk = manager.getRnsKeyPair(rns_channel_).publicKey;
            } else {
                cc = manager.getComparisonCryptoContext();
                pk = manager.getComparisonPublicKey();
            }
            if (!cc || !pk) {
                throw std::runtime_error("BFVRadixComparisonNode: comparison crypto context unavailable");
            }

            // Create ones plaintext for negation
            Plaintext ones_plain = cachedUniformPt(cc, 1, pack_slots);

            Ciphertext<DCRTPoly> indicator_cipher;
            switch (style_) {
                case FheFilterStyle::PolynomialLE:
                    // A <= B: direct LE comparison
                    indicator_cipher = polynomialComparisonLe(cc, pk, threshold_digit_ciphers_, radix_columns, pack_slots, radix_base_);
                    break;
                case FheFilterStyle::PolynomialGT:
                    // A > B: NOT(A <= B) = 1 - LE(A, B)
                    indicator_cipher = polynomialComparisonLe(cc, pk, threshold_digit_ciphers_, radix_columns, pack_slots, radix_base_);
                    indicator_cipher = cc->EvalSub(ones_plain, indicator_cipher);
                    break;
                case FheFilterStyle::PolynomialGE:
                    // A >= B: B <= A (swap operands)
                    // This means we compare threshold <= column_value
                    // polynomialComparisonLe computes: column <= threshold
                    // For GE, we need: column >= threshold, which is: threshold <= column
                    // So we pass column values as "threshold" and threshold as "column"
                    // But that's complex because threshold is encrypted...
                    // Simpler: A >= B is NOT(A < B) = NOT(NOT(A >= B)) = NOT(NOT(B <= A - 1))
                    // Actually: A >= B = NOT(A < B) where A < B = NOT(A >= B)
                    // Let's use: A >= B = NOT(B > A) = NOT(NOT(B <= A)) = B <= A
                    // But B is encrypted threshold, A is plaintext column
                    // Easier: A >= B = 1 - (B > A) = 1 - GT(B, A)
                    // GT(B, A) = 1 - LE(B, A), so GE(A, B) = LE(B, A)
                    // We compute LE with swapped roles: threshold_digits as "column", radix_columns as "threshold"
                    // Actually the polynomial compares column_values vs threshold_digits
                    // For GE: we want result=1 when column >= threshold
                    // This equals NOT(column < threshold) = NOT(NOT(column >= threshold))
                    // Using relation: A < B iff NOT(A >= B)
                    // A >= B is equivalent to NOT(A < B), and A < B is NOT(A >= B)
                    // So: GE(A,B) = NOT(LT(A,B)) = NOT(NOT(LE(A-1,B))) 
                    // Simpler approach: GE(A, B) = LE(B, A) but B is encrypted...
                    // Let's just compute GT(A, B-1) which equals GE(A, B) for integers
                    // Or: A >= B means A > B-1, so GT works. But threshold is encrypted.
                    // Actually simplest: NOT(LT(A, B)) = NOT(1 - GE(A, B)) = GE(A, B)
                    // Let's compute: GE(A, B) = 1 - LT(A, B)
                    // And LT(A, B) is GT(B, A) for encrypted B... still complex.
                    // Practical approach: GE(col, threshold) = NOT(col < threshold)
                    // col < threshold means col <= threshold - 1
                    // But we can't modify encrypted threshold.
                    // Use polynomial GT directly: GT(col, threshold) then negate
                    // Actually we don't have GT polynomial... we have LE.
                    // A >= B equivalent to NOT(B > A)
                    // B > A means NOT(B <= A)
                    // So A >= B = NOT(NOT(B <= A)) = B <= A
                    // We need to swap operands conceptually in the comparison.
                    // In polynomialComparisonLe: it computes diff = column - threshold, then checks diff <= 0
                    // For GE: we want column >= threshold, i.e., diff >= 0
                    // This is equivalent to -(diff) <= 0, i.e., threshold - column <= 0
                    // So we can negate the diff in the polynomial computation.
                    // For now, let's implement as: GE = NOT(GT(threshold, column)) = NOT(NOT(LE(threshold, column)))
                    // = LE(threshold, column), but threshold is encrypted, column is plain...
                    // The easiest practical solution: compute as 1 - LT
                    // LT(A,B) = GT(B,A), and GT(B,A) = 1 - LE(B,A)
                    // We can compute with inverted subtraction: instead of A - B, use B - A
                    // Let's just use the negated diff approach in a helper function.
                    {
                        // GE(A, B) = NOT(LT(A, B))
                        // LT(A, B) = 1 - GE(A, B) = 1 - NOT(LT(A, B))... circular
                        // Direct: GE(A, B) means A - B >= 0, so we check if diff is non-negative
                        // In LE, we check A - B <= 0 (returns 1 if A <= B)
                        // For GE, we want A - B >= 0, which is -(A-B) <= 0, i.e., B - A <= 0
                        // So GE(A, B) = LE(B, A) with swapped operands in diff calculation
                        // In polynomialComparisonLe, diff = plain - cipher
                        // For GE, we want diff = cipher - plain
                        // Let's compute: polynomialComparisonLe with negated diff
                        indicator_cipher = polynomialComparisonGe(cc, pk, threshold_digit_ciphers_, radix_columns, pack_slots, radix_base_);
                    }
                    break;
                case FheFilterStyle::PolynomialLT:
                    // A < B: NOT(A >= B) = 1 - GE(A, B)
                    indicator_cipher = polynomialComparisonGe(cc, pk, threshold_digit_ciphers_, radix_columns, pack_slots, radix_base_);
                    indicator_cipher = cc->EvalSub(ones_plain, indicator_cipher);
                    break;
                case FheFilterStyle::PolynomialEQ:
                    // A = B: EQ chain (all digits must match)
                    indicator_cipher = polynomialComparisonEqual(cc, pk, threshold_digit_ciphers_, radix_columns, pack_slots, radix_base_);
                    break;
                default:
                    throw std::runtime_error("BFVRadixComparisonNode: unsupported filter style");
            }

            auto chunk = std::make_shared<FheColumnChunk>(indicator_cipher, q_params_, type_desc_, effective_count);
            return chunk;
        }

        std::string toString() const override {
            std::string op;
            switch (style_) {
                case FheFilterStyle::PolynomialLE:
                    op = "<=";
                    break;
                case FheFilterStyle::PolynomialLT:
                    op = "<";
                    break;
                case FheFilterStyle::PolynomialGE:
                    op = ">=";
                    break;
                case FheFilterStyle::PolynomialGT:
                    op = ">";
                    break;
            }
            return column_name_ + " " + op + " ? (BFV)";
        }

        ExpressionKind kind() const override {
            switch (style_) {
                case FheFilterStyle::PolynomialLE:
                    return ExpressionKind::LEQ;
                case FheFilterStyle::PolynomialLT:
                    return ExpressionKind::LT;
                case FheFilterStyle::PolynomialGE:
                    return ExpressionKind::GEQ;
                case FheFilterStyle::PolynomialGT:
                    return ExpressionKind::GT;
                default:
            return ExpressionKind::LEQ;
            }
        }

        std::shared_ptr<SIMDExpressionNode<FheColumnChunk>> clone() const override {
            return std::make_shared<BFVRadixComparisonNode>(*this);
        }

    private:
        QueryFieldDesc field_desc_;
        std::string column_name_;
        std::vector<Ciphertext<DCRTPoly>> threshold_digit_ciphers_;
        FheFilterStyle style_;
        size_t radix_base_;
        size_t num_digits_;
        size_t rns_channel_;
        QuantizationParams q_params_;
        FheTypeDescriptor type_desc_;

        // Radix column cache — avoids rebuilding radix decomposition for same chunk
        mutable std::unordered_map<size_t, std::vector<std::vector<int64_t>>> radix_cache_;
        mutable std::mutex radix_cache_mutex_;
    };
    
    // Keep old name for backward compatibility
    using BFVRadixLessEqualNode = BFVRadixComparisonNode;
    
    /**
     * Helper function to process a single chunk for filter operation.
     * Implements tree-based reduction for predicate combination to minimize multiplicative depth.
     * Supports parallel predicate evaluation when enable_predicate_parallelism is true.
     */
    void processChunkForFilter(
        size_t chunk_idx,
        const std::vector<SIMDFheGenericExpression>& predicates,
        std::shared_ptr<FheColumnTable> input,
        std::shared_ptr<PlainColumnTable> plain_snapshot,
        std::shared_ptr<FheColumn> existing_dummy_tag,
        const CryptoContext<DCRTPoly>& cc,
        const PublicKey<DCRTPoly>& pk,
        const Ciphertext<DCRTPoly>& ones_cipher_shared,
        size_t pack_slots,
        size_t row_count,
        const std::string& dummy_tag_name,
        std::vector<std::shared_ptr<FheColumnChunk>>& chunk_results,
        bool enable_predicate_parallelism,
        const std::vector<int>& or_group_ids = {}) {
        
        Ciphertext<DCRTPoly> new_indicator_cipher;
        QuantizationParams chunk_params{};
        FheTypeDescriptor chunk_desc{};
        size_t effective_count = std::min(pack_slots, row_count - chunk_idx * pack_slots);
        
        // Pre-allocate vector to allow thread-safe random access in parallel loop
        std::vector<Ciphertext<DCRTPoly>> predicate_results(predicates.size());
        
        // Metadata capture flags (thread-safe)
        bool metadata_captured = false;
        std::mutex metadata_mutex;
        
        // Independent Predicate Evaluation: can be parallelized when chunks are few
        // If enable_predicate_parallelism is true, multiple predicates run concurrently
        #pragma omp parallel for schedule(dynamic) if(enable_predicate_parallelism)
        for (size_t i = 0; i < predicates.size(); ++i) {
            auto chunk = predicates[i].call(input.get(), chunk_idx);
            if (!chunk) {
                throw std::runtime_error("FheFilter: predicate returned null chunk");
            }
            predicate_results[i] = chunk->getCiphertext();
            
            // Capture metadata from the first available chunk (thread-safe)
            if (!metadata_captured) {
                std::lock_guard<std::mutex> lock(metadata_mutex);
                if (!metadata_captured) {
                    chunk_params = chunk->q_params();
                    chunk_desc = chunk->type_desc;
                    effective_count = chunk->packed_count;
                    metadata_captured = true;
                }
            }
        }
        
        // Predicate combination with OR group support.
        // Predicates sharing the same or_group_id are ORed (EvalAdd, depth 0 for mutually exclusive values).
        // Different groups are ANDed (EvalMult tree reduction).
        if (predicate_results.empty()) {
            auto ones_enc = cachedUniformPt(cc, 1, pack_slots);
            new_indicator_cipher = cc->Encrypt(pk, ones_enc);
            QuantizationParams q_params{};
            q_params.simdSlots = static_cast<unsigned int>(pack_slots);
            chunk_params = q_params;
            chunk_desc = FheTypeDescriptor(FheDataType::BOOLEAN, FheEncodingType::BFV_PACKED_ENCODING);
            effective_count = std::min(pack_slots, row_count - chunk_idx * pack_slots);
        } else if (predicate_results.size() == 1) {
            new_indicator_cipher = predicate_results[0];
        } else {
            // Phase 1: collapse OR groups via EvalAdd
            std::vector<Ciphertext<DCRTPoly>> and_operands;
            if (!or_group_ids.empty()) {
                std::map<int, Ciphertext<DCRTPoly>> group_results;
                for (size_t i = 0; i < predicate_results.size(); ++i) {
                    int gid = or_group_ids[i];
                    auto it = group_results.find(gid);
                    if (it == group_results.end())
                        group_results[gid] = predicate_results[i];
                    else
                        it->second = cc->EvalAdd(it->second, predicate_results[i]);
                }
                and_operands.reserve(group_results.size());
                for (auto& [gid, cipher] : group_results) and_operands.push_back(std::move(cipher));
            } else {
                and_operands = std::move(predicate_results);
            }

            // Phase 2: AND tree reduction (EvalMult)
            while (and_operands.size() > 1) {
                std::vector<Ciphertext<DCRTPoly>> next_level;
                next_level.reserve((and_operands.size() + 1) / 2);
                for (size_t i = 0; i < and_operands.size(); i += 2) {
                    if (i + 1 < and_operands.size())
                        next_level.push_back(cc->EvalMultAndRelinearize(and_operands[i], and_operands[i + 1]));
                    else
                        next_level.push_back(and_operands[i]);
                }
                and_operands = std::move(next_level);
            }
            new_indicator_cipher = and_operands[0];
        }
        
        // Mask out padding slots: slots beyond effective_count must be 0 (invalid). Otherwise padding (0)
        // satisfies predicates like "<= 1998" and gets counted as valid.
        if (effective_count < pack_slots) {
            std::vector<int64_t> valid_mask_vec(pack_slots, 0);
            for (size_t i = 0; i < effective_count; ++i) valid_mask_vec[i] = 1;
            Plaintext valid_mask_pt = cc->MakePackedPlaintext(valid_mask_vec);
            new_indicator_cipher = cc->EvalMult(new_indicator_cipher, valid_mask_pt);
        }
        
        // FHE convention: 1=valid, 0=dummy. Predicate returns 1 when satisfied → valid = existing * predicate.
        // (No inversion: 1=satisfied keeps row valid, 0=not satisfied makes row dummy.)
        Ciphertext<DCRTPoly> result_cipher;
        if (existing_dummy_tag && chunk_idx < existing_dummy_tag->getFheChunks().size()) {
            const auto& existing_chunk = existing_dummy_tag->getFheChunks()[chunk_idx];
            if (existing_chunk) {
                result_cipher = cc->EvalMultAndRelinearize(existing_chunk->getCiphertext(), new_indicator_cipher);
            } else {
                result_cipher = new_indicator_cipher;
            }
        } else {
            auto plain_dummy_col = plain_snapshot->getPlainColumn(dummy_tag_name);
            if (plain_dummy_col && chunk_idx < plain_dummy_col->getPlainChunks().size()) {
                const auto& plain_chunk = plain_dummy_col->getPlainChunks()[chunk_idx];
                if (plain_chunk) {
                    std::vector<int64_t> dummy_vec;
                    dummy_vec.reserve(pack_slots);
                    for (size_t i = 0; i < effective_count && i < plain_chunk->getValues().size(); ++i) {
                        bool val = plain_chunk->getValues()[i].getValue<bool>();
                        dummy_vec.push_back(val ? 1 : 0);
                    }
                    while (dummy_vec.size() < pack_slots) {
                        dummy_vec.push_back(0);
                    }
                    Plaintext dummy_plain = cc->MakePackedPlaintext(dummy_vec);
                    Ciphertext<DCRTPoly> encrypted_dummy = cc->Encrypt(pk, dummy_plain);
                    result_cipher = cc->EvalMultAndRelinearize(encrypted_dummy, new_indicator_cipher);
                } else {
                    result_cipher = new_indicator_cipher;
                }
            } else {
                result_cipher = new_indicator_cipher;
            }
        }
        
        // Store result
        chunk_results[chunk_idx] = std::make_shared<FheColumnChunk>(result_cipher, chunk_params, chunk_desc, effective_count);
    }

    /// Returns dummy_tag ciphertext for one channel (for multi-channel filter; parallel over channels).
    Ciphertext<DCRTPoly> processChunkForFilterChannel(
        size_t chunk_idx,
        size_t channel,
        const std::vector<SIMDFheGenericExpression>& predicates_ch,
        std::shared_ptr<FheColumnTable> input,
        std::shared_ptr<PlainColumnTable> plain_snapshot,
        std::shared_ptr<FheColumn> existing_dummy_tag,
        size_t pack_slots,
        size_t row_count,
        const std::string& dummy_tag_name,
        const CryptoContext<DCRTPoly>& cc,
        const PublicKey<DCRTPoly>& pk,
        const Ciphertext<DCRTPoly>& ones_cipher,
        ChannelOpStats* op_stats,
        const std::vector<int>& or_group_ids = {}) {
        Ciphertext<DCRTPoly> new_indicator_cipher;
        size_t effective_count = std::min(pack_slots, row_count - chunk_idx * pack_slots);
        std::vector<Ciphertext<DCRTPoly>> predicate_results(predicates_ch.size());
        for (size_t i = 0; i < predicates_ch.size(); ++i) {
            auto chunk = predicates_ch[i].call(input.get(), chunk_idx);
            if (!chunk) throw std::runtime_error("FheFilter: predicate returned null chunk");
            predicate_results[i] = chunk->getCiphertext(0);
        }
        if (predicate_results.empty()) {
            auto ones_enc2 = cachedUniformPt(cc, 1, pack_slots);
            new_indicator_cipher = cc->Encrypt(pk, ones_enc2);
        } else if (predicate_results.size() == 1) {
            new_indicator_cipher = predicate_results[0];
        } else {
            // Phase 1: collapse OR groups via EvalAdd
            std::vector<Ciphertext<DCRTPoly>> and_operands;
            if (!or_group_ids.empty()) {
                std::map<int, Ciphertext<DCRTPoly>> group_results;
                for (size_t i = 0; i < predicate_results.size(); ++i) {
                    int gid = or_group_ids[i];
                    auto it = group_results.find(gid);
                    if (it == group_results.end())
                        group_results[gid] = predicate_results[i];
                    else
                        it->second = cc->EvalAdd(it->second, predicate_results[i]);
                }
                and_operands.reserve(group_results.size());
                for (auto& [gid, cipher] : group_results) and_operands.push_back(std::move(cipher));
            } else {
                and_operands = std::move(predicate_results);
            }

            // Phase 2: AND tree reduction (EvalMult)
            while (and_operands.size() > 1) {
                std::vector<Ciphertext<DCRTPoly>> next;
                for (size_t i = 0; i < and_operands.size(); i += 2) {
                    if (i + 1 < and_operands.size()) {
                        next.push_back(cc->EvalMultAndRelinearize(and_operands[i], and_operands[i + 1]));
                        if (op_stats) {
                            op_stats->multCtCt();
                            op_stats->relin();
                            op_stats->keyswitch();
                            op_stats->modreduce();
                        }
                    } else {
                        next.push_back(and_operands[i]);
                    }
                }
                and_operands = std::move(next);
            }
            new_indicator_cipher = and_operands[0];
        }
        // Mask out padding slots (multi-channel): same as single-channel to avoid padding satisfying predicate.
        if (effective_count < pack_slots) {
            std::vector<int64_t> valid_mask_vec(pack_slots, 0);
            for (size_t i = 0; i < effective_count; ++i) valid_mask_vec[i] = 1;
            Plaintext valid_mask_pt = cc->MakePackedPlaintext(valid_mask_vec);
            new_indicator_cipher = cc->EvalMult(new_indicator_cipher, valid_mask_pt);
            if (op_stats) op_stats->multCtPt();
        }
        // Same as single-channel: valid = existing * predicate (1=satisfied → keep valid, no inversion).
        Ciphertext<DCRTPoly> result_cipher;
        if (existing_dummy_tag && chunk_idx < existing_dummy_tag->getFheChunks().size()) {
            const auto& existing_chunk = existing_dummy_tag->getFheChunks()[chunk_idx];
            if (existing_chunk && channel < existing_chunk->getRnsLevel()) {
                auto existing_ct = existing_chunk->getCiphertext(channel);
                result_cipher = cc->EvalMultAndRelinearize(existing_ct, new_indicator_cipher);
                if (op_stats) {
                    op_stats->multCtCt();
                    op_stats->relin();
                    op_stats->keyswitch();
                    op_stats->modreduce();
                }
            } else {
                result_cipher = new_indicator_cipher;
            }
        } else {
            auto plain_dummy_col = plain_snapshot->getPlainColumn(dummy_tag_name);
            if (plain_dummy_col && chunk_idx < plain_dummy_col->getPlainChunks().size()) {
                const auto& plain_chunk = plain_dummy_col->getPlainChunks()[chunk_idx];
                if (plain_chunk) {
                    std::vector<int64_t> dummy_vec(pack_slots, 0);
                    for (size_t i = 0; i < effective_count && i < plain_chunk->getValues().size(); ++i)
                        dummy_vec[i] = plain_chunk->getValues()[i].getValue<bool>() ? 1 : 0;
                    auto enc_dummy = cc->Encrypt(pk, cc->MakePackedPlaintext(dummy_vec));
                    result_cipher = cc->EvalMultAndRelinearize(enc_dummy, new_indicator_cipher);
                    if (op_stats) {
                        op_stats->multCtCt();
                        op_stats->relin();
                        op_stats->keyswitch();
                        op_stats->modreduce();
                    }
                } else {
                    result_cipher = new_indicator_cipher;
                }
            } else {
                result_cipher = new_indicator_cipher;
            }
        }
        return result_cipher;
    }
} // namespace

FheFilter::FheFilter(ColumnOperator<void>* child,
                     const std::vector<SIMDFheGenericExpression>& predicates,
                     std::string indicator_name)
        : ColumnOperator<void>(SortDefinition{}, 0),
          indicator_name_(std::move(indicator_name)),
          predicates_(predicates) {
    if (!child) {
        throw std::invalid_argument("FheFilter: child operator is null");
    }
    setChild(child, 0);
    output_schema_ = child->getOutputSchema();
    output_cardinality_ = child->getOutputCardinality();
    sort_definition_ = child->getSortOrder();
}

// Constructor accepting shared_ptr<FheColumnTable> directly (for testing convenience)
FheFilter::FheFilter(std::shared_ptr<FheColumnTable> input_table,
                     const std::vector<SIMDFheGenericExpression>& predicates,
                     std::string indicator_name)
        : ColumnOperator<void>(SortDefinition{}, 0),
          indicator_name_(std::move(indicator_name)),
          predicates_(predicates),
          input_(input_table) {
    if (!input_table) {
        throw std::invalid_argument("FheFilter: input table is null");
    }
    output_schema_ = input_table->getSchema();
    output_cardinality_ = input_table->getRowCount();
}

FheFilter::FheFilter(ColumnOperator<void>* child,
                     const std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>>& threshold_digits,
                     const std::vector<std::string>& column_names,
                     const std::vector<size_t>& radix_bases,
                     const std::vector<std::string>& predicate_types,
                     std::string indicator_name,
                     const std::vector<std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>>>& threshold_digits_per_channel,
                     const std::vector<int>& or_group_ids)
        : ColumnOperator<void>(SortDefinition{}, 0),
          indicator_name_(std::move(indicator_name)),
          deferred_threshold_digits_(threshold_digits),
          deferred_column_names_(column_names),
          deferred_radix_bases_(radix_bases),
          deferred_predicate_types_(predicate_types),
          deferred_threshold_digits_per_channel_(threshold_digits_per_channel),
          or_group_ids_(or_group_ids) {
    if (!child) {
        throw std::invalid_argument("FheFilter: child operator is null");
    }
    // Default to "less_equal" if predicate_types is empty
    if (deferred_predicate_types_.empty()) {
        deferred_predicate_types_.resize(threshold_digits.size(), "less_equal");
    }
    setChild(child, 0);
    output_schema_ = child->getOutputSchema();
    output_cardinality_ = child->getOutputCardinality();
    sort_definition_ = child->getSortOrder();
}

void FheFilter::preparePredicates() {
    if (predicates_prepared_) return;

    // Ensure input_ is set
    if (!input_) {
        ColumnOperator<void>* child_op = getChild(0);
        if (!child_op) {
            throw std::runtime_error("FheFilter::preparePredicates: child operator is null");
        }
        auto child_result = child_op->runSelf();
        input_ = std::dynamic_pointer_cast<FheColumnTable>(child_result);
        if (!input_) {
            throw std::runtime_error("FheFilter::preparePredicates: child must return FheColumnTable");
        }
    }

    // Build predicates from deferred thresholds
    if (predicates_.empty() && !deferred_threshold_digits_.empty()) {
        const QuerySchema& schema = input_->getSchema();
        for (size_t i = 0; i < deferred_threshold_digits_.size(); ++i) {
            const std::string& pred_type = deferred_predicate_types_[i];
            if (pred_type == "less_equal")
                predicates_.push_back(makePolynomialLessEqualPredicate(schema, deferred_column_names_[i], deferred_threshold_digits_[i], deferred_radix_bases_[i]));
            else if (pred_type == "less_than")
                predicates_.push_back(makePolynomialLessThanPredicate(schema, deferred_column_names_[i], deferred_threshold_digits_[i], deferred_radix_bases_[i]));
            else if (pred_type == "greater_equal")
                predicates_.push_back(makePolynomialGreaterEqualPredicate(schema, deferred_column_names_[i], deferred_threshold_digits_[i], deferred_radix_bases_[i]));
            else if (pred_type == "greater_than")
                predicates_.push_back(makePolynomialGreaterThanPredicate(schema, deferred_column_names_[i], deferred_threshold_digits_[i], deferred_radix_bases_[i]));
            else if (pred_type == "equal")
                predicates_.push_back(makePolynomialEqualPredicate(schema, deferred_column_names_[i], deferred_threshold_digits_[i], deferred_radix_bases_[i]));
            else
                throw std::runtime_error("FheFilter: unsupported predicate type: " + pred_type);
        }
        // Build per-channel predicates
        if (!deferred_threshold_digits_per_channel_.empty() && deferred_threshold_digits_per_channel_[0].size() > 1) {
            size_t num_channels = deferred_threshold_digits_per_channel_[0].size();
            predicates_per_channel_.resize(num_channels);
            for (size_t ch = 0; ch < num_channels; ++ch) {
                for (size_t i = 0; i < deferred_threshold_digits_per_channel_.size(); ++i) {
                    const std::string& pred_type = deferred_predicate_types_[i];
                    const auto& thresh = deferred_threshold_digits_per_channel_[i][ch];
                    if (pred_type == "less_equal")
                        predicates_per_channel_[ch].push_back(makePolynomialLessEqualPredicate(schema, deferred_column_names_[i], thresh, deferred_radix_bases_[i], ch));
                    else if (pred_type == "less_than")
                        predicates_per_channel_[ch].push_back(makePolynomialLessThanPredicate(schema, deferred_column_names_[i], thresh, deferred_radix_bases_[i], ch));
                    else if (pred_type == "greater_equal")
                        predicates_per_channel_[ch].push_back(makePolynomialGreaterEqualPredicate(schema, deferred_column_names_[i], thresh, deferred_radix_bases_[i], ch));
                    else if (pred_type == "greater_than")
                        predicates_per_channel_[ch].push_back(makePolynomialGreaterThanPredicate(schema, deferred_column_names_[i], thresh, deferred_radix_bases_[i], ch));
                    else if (pred_type == "equal")
                        predicates_per_channel_[ch].push_back(makePolynomialEqualPredicate(schema, deferred_column_names_[i], thresh, deferred_radix_bases_[i], ch));
                    else
                        throw std::runtime_error("FheFilter: unsupported predicate type: " + pred_type);
                }
            }
        }
    }

    // Build DNF group predicates
    if (!dnf_groups_.empty()) {
        const QuerySchema& schema = input_->getSchema();
        for (size_t g = 0; g < dnf_groups_.size(); ++g) {
            const auto& grp = dnf_groups_[g];
            std::vector<SIMDFheGenericExpression> grp_preds;
            for (size_t i = 0; i < grp.threshold_digits.size(); ++i) {
                const std::string& pred_type = grp.predicate_types[i];
                if (pred_type == "less_equal")
                    grp_preds.push_back(makePolynomialLessEqualPredicate(schema, grp.column_names[i], grp.threshold_digits[i], grp.radix_bases[i]));
                else if (pred_type == "less_than")
                    grp_preds.push_back(makePolynomialLessThanPredicate(schema, grp.column_names[i], grp.threshold_digits[i], grp.radix_bases[i]));
                else if (pred_type == "greater_equal")
                    grp_preds.push_back(makePolynomialGreaterEqualPredicate(schema, grp.column_names[i], grp.threshold_digits[i], grp.radix_bases[i]));
                else if (pred_type == "greater_than")
                    grp_preds.push_back(makePolynomialGreaterThanPredicate(schema, grp.column_names[i], grp.threshold_digits[i], grp.radix_bases[i]));
                else if (pred_type == "equal")
                    grp_preds.push_back(makePolynomialEqualPredicate(schema, grp.column_names[i], grp.threshold_digits[i], grp.radix_bases[i]));
                else
                    throw std::runtime_error("FheFilter: unsupported DNF predicate type: " + pred_type);
            }
            prepared_dnf_group_predicates_.push_back(std::move(grp_preds));
            prepared_dnf_group_or_ids_.push_back(grp.or_group_ids);

            if (!grp.threshold_digits_per_channel.empty() && grp.threshold_digits_per_channel[0].size() > 1) {
                size_t num_ch = grp.threshold_digits_per_channel[0].size();
                std::vector<std::vector<SIMDFheGenericExpression>> ch_preds(num_ch);
                for (size_t ch = 0; ch < num_ch; ++ch) {
                    for (size_t i = 0; i < grp.threshold_digits_per_channel.size(); ++i) {
                        const std::string& pred_type = grp.predicate_types[i];
                        const auto& thresh = grp.threshold_digits_per_channel[i][ch];
                        if (pred_type == "less_equal")
                            ch_preds[ch].push_back(makePolynomialLessEqualPredicate(schema, grp.column_names[i], thresh, grp.radix_bases[i], ch));
                        else if (pred_type == "less_than")
                            ch_preds[ch].push_back(makePolynomialLessThanPredicate(schema, grp.column_names[i], thresh, grp.radix_bases[i], ch));
                        else if (pred_type == "greater_equal")
                            ch_preds[ch].push_back(makePolynomialGreaterEqualPredicate(schema, grp.column_names[i], thresh, grp.radix_bases[i], ch));
                        else if (pred_type == "greater_than")
                            ch_preds[ch].push_back(makePolynomialGreaterThanPredicate(schema, grp.column_names[i], thresh, grp.radix_bases[i], ch));
                        else if (pred_type == "equal")
                            ch_preds[ch].push_back(makePolynomialEqualPredicate(schema, grp.column_names[i], thresh, grp.radix_bases[i], ch));
                        else
                            throw std::runtime_error("FheFilter: unsupported DNF predicate type: " + pred_type);
                    }
                }
                prepared_dnf_group_predicates_per_channel_.push_back(std::move(ch_preds));
            } else {
                prepared_dnf_group_predicates_per_channel_.push_back({});
            }
        }
    }

    // Store state for computeChunkIndicator
    prepared_plain_snapshot_ = input_->getPlainSnapshot();
    if (!prepared_plain_snapshot_) {
        throw std::runtime_error("FheFilter::preparePredicates: input table lacks plain snapshot");
    }

    FheManager& manager = FheManager::getInstance();
    prepared_pack_slots_ = manager.getBFVComparisonBatchSize();
    prepared_row_count_ = prepared_plain_snapshot_->getRowCount();
    prepared_chunk_count_ = (prepared_row_count_ + prepared_pack_slots_ - 1) / prepared_pack_slots_;

    prepared_existing_dummy_tag_ = input_->getFheColumn("dummy_tag");
    prepared_use_multi_channel_ = !predicates_per_channel_.empty();

    if (prepared_use_multi_channel_) {
        size_t num_ch = predicates_per_channel_.size();
        prepared_ones_cipher_rns_.resize(num_ch);
        for (size_t ch = 0; ch < num_ch; ++ch) {
            auto cc_ch = manager.getRnsContext(ch);
            auto pk_ch = manager.getRnsKeyPair(ch).publicKey;
            auto ones_rns_pt = cachedUniformPt(cc_ch, 1, prepared_pack_slots_);
            prepared_ones_cipher_rns_[ch] = cc_ch->Encrypt(pk_ch, ones_rns_pt);
        }
    }
    prepared_ones_cipher_shared_ = manager.getOnesCipher(prepared_pack_slots_);

    predicates_prepared_ = true;
}

std::shared_ptr<FheColumnChunk> FheFilter::computeChunkIndicator(size_t chunk_idx) {
    assert(predicates_prepared_);
    FheManager& manager = FheManager::getInstance();

    QuantizationParams chunk_params{};
    chunk_params.simdSlots = static_cast<unsigned int>(prepared_pack_slots_);
    FheTypeDescriptor chunk_desc(FheDataType::BOOLEAN, FheEncodingType::BFV_PACKED_ENCODING);
    size_t effective_count = std::min(prepared_pack_slots_, prepared_row_count_ - chunk_idx * prepared_pack_slots_);

    std::shared_ptr<FheColumnChunk> result;

    if (prepared_use_multi_channel_) {
        size_t num_ch = predicates_per_channel_.size();
        std::vector<Ciphertext<DCRTPoly>> channel_cts(num_ch);

        for (size_t ch = 0; ch < num_ch; ++ch) {
            auto cc_ch = manager.getRnsContext(ch);
            auto pk_ch = manager.getRnsKeyPair(ch).publicKey;
            channel_cts[ch] = processChunkForFilterChannel(
                chunk_idx, ch, predicates_per_channel_[ch], input_, prepared_plain_snapshot_,
                prepared_existing_dummy_tag_, prepared_pack_slots_, prepared_row_count_, "dummy_tag",
                cc_ch, pk_ch, prepared_ones_cipher_rns_[ch], nullptr,
                or_group_ids_);
        }
        result = std::make_shared<FheColumnChunk>(
            std::move(channel_cts), chunk_params, chunk_desc, effective_count);
    } else {
        // Single-channel: use processChunkForFilter which writes to chunk_results vector
        std::vector<std::shared_ptr<FheColumnChunk>> temp_results(prepared_chunk_count_);
        auto cc = manager.getComparisonCryptoContext();
        auto pk = manager.getComparisonPublicKey();
        processChunkForFilter(chunk_idx, predicates_, input_, prepared_plain_snapshot_,
                             prepared_existing_dummy_tag_, cc, pk, prepared_ones_cipher_shared_,
                             prepared_pack_slots_, prepared_row_count_, "dummy_tag", temp_results, false,
                             or_group_ids_);
        result = temp_results[chunk_idx];
    }

    // Apply DNF if needed
    if (!prepared_dnf_group_predicates_.empty() && result) {
        auto evaluateDnfForChannel = [&](size_t ci,
                                         const std::vector<std::vector<SIMDFheGenericExpression>>& grp_preds_all,
                                         const CryptoContext<DCRTPoly>& eval_cc,
                                         size_t cipher_idx) -> Ciphertext<DCRTPoly> {
            Ciphertext<DCRTPoly> dnf_or_result;
            bool first_group = true;
            for (size_t g = 0; g < grp_preds_all.size(); ++g) {
                const auto& grp_preds = grp_preds_all[g];
                const auto& grp_or_ids = prepared_dnf_group_or_ids_[g];

                std::vector<Ciphertext<DCRTPoly>> pred_results(grp_preds.size());
                for (size_t i = 0; i < grp_preds.size(); ++i) {
                    auto chunk = grp_preds[i].call(input_.get(), ci);
                    if (!chunk) throw std::runtime_error("FheFilter: DNF predicate returned null chunk");
                    pred_results[i] = chunk->getCiphertext(cipher_idx);
                }

                std::vector<Ciphertext<DCRTPoly>> and_operands;
                if (!grp_or_ids.empty()) {
                    std::map<int, Ciphertext<DCRTPoly>> group_results;
                    for (size_t i = 0; i < pred_results.size(); ++i) {
                        int gid = grp_or_ids[i];
                        auto it = group_results.find(gid);
                        if (it == group_results.end())
                            group_results[gid] = pred_results[i];
                        else
                            it->second = eval_cc->EvalAdd(it->second, pred_results[i]);
                    }
                    and_operands.reserve(group_results.size());
                    for (auto& [gid, cipher] : group_results) and_operands.push_back(std::move(cipher));
                } else {
                    and_operands = std::move(pred_results);
                }

                while (and_operands.size() > 1) {
                    std::vector<Ciphertext<DCRTPoly>> next;
                    next.reserve((and_operands.size() + 1) / 2);
                    for (size_t i = 0; i < and_operands.size(); i += 2) {
                        if (i + 1 < and_operands.size())
                            next.push_back(eval_cc->EvalMultAndRelinearize(and_operands[i], and_operands[i + 1]));
                        else
                            next.push_back(and_operands[i]);
                    }
                    and_operands = std::move(next);
                }

                if (first_group) {
                    dnf_or_result = and_operands[0];
                    first_group = false;
                } else {
                    dnf_or_result = eval_cc->EvalAdd(dnf_or_result, and_operands[0]);
                }
            }
            return dnf_or_result;
        };

        if (prepared_use_multi_channel_ && !prepared_dnf_group_predicates_per_channel_.empty() &&
            !prepared_dnf_group_predicates_per_channel_[0].empty()) {
            size_t num_ch = predicates_per_channel_.size();
            std::vector<Ciphertext<DCRTPoly>> dnf_cts(num_ch);
            for (size_t ch = 0; ch < num_ch; ++ch) {
                auto cc_ch = manager.getRnsContext(ch);
                std::vector<std::vector<SIMDFheGenericExpression>> grp_preds_for_ch(prepared_dnf_group_predicates_per_channel_.size());
                for (size_t g = 0; g < prepared_dnf_group_predicates_per_channel_.size(); ++g) {
                    grp_preds_for_ch[g] = prepared_dnf_group_predicates_per_channel_[g][ch];
                }
                auto dnf_or = evaluateDnfForChannel(chunk_idx, grp_preds_for_ch, cc_ch, 0);
                auto main_ct = result->getCiphertext(ch);
                dnf_cts[ch] = cc_ch->EvalMultAndRelinearize(main_ct, dnf_or);
            }
            result = std::make_shared<FheColumnChunk>(
                std::move(dnf_cts), chunk_params, chunk_desc, effective_count);
        } else {
            auto cc = manager.getComparisonCryptoContext();
            auto dnf_or = evaluateDnfForChannel(chunk_idx, prepared_dnf_group_predicates_, cc, 0);
            auto main_ct = result->getCiphertext();
            auto combined = cc->EvalMultAndRelinearize(main_ct, dnf_or);
            result = std::make_shared<FheColumnChunk>(combined, chunk_params, chunk_desc, effective_count);
        }
    }

    return result;
}

size_t FheFilter::getChunkCount() const {
    if (predicates_prepared_) return prepared_chunk_count_;
    // Fallback: compute from input if available
    if (input_) {
        auto ps = input_->getPlainSnapshot();
        if (ps) {
            size_t slots = FheManager::getInstance().getBFVComparisonBatchSize();
            return (ps->getRowCount() + slots - 1) / slots;
        }
    }
    return 0;
}

std::shared_ptr<PlainColumnTable> FheFilter::getPlainSnapshot() const {
    if (predicates_prepared_) return prepared_plain_snapshot_;
    if (input_) return input_->getPlainSnapshot();
    return nullptr;
}

const std::vector<BinGroupMetadata>& FheFilter::getBinMetadata() const {
    return input_->getBinMetadata();
}

const std::vector<int32_t>& FheFilter::getBinGroupByOrdinals() const {
    return input_->getBinGroupByOrdinals();
}

std::shared_ptr<ColumnTableBase<void>> FheFilter::runSelf() {
    // If input_ is already set (from direct constructor), use it; otherwise get from child
    if (!input_) {
        // Execute child operator to get input table
        ColumnOperator<void>* child_op = getChild(0);
        if (!child_op) {
            throw std::runtime_error("FheFilter: child operator is null");
        }

        auto child_result = child_op->runSelf();
        input_ = std::dynamic_pointer_cast<FheColumnTable>(child_result);
        if (!input_) {
            throw std::runtime_error("FheFilter: child operator must return FheColumnTable");
        }
    }

    // Start timing only for this operator's own work (exclude child runtime)
    startTiming();

    // Ensure predicates are prepared (idempotent)
    preparePredicates();

    // Create predicates from deferred information if needed (predicates not provided at construction)
    // Predicate building done by preparePredicates() above.
    // Use prepared_ members for DNF groups in the chunk loop below.
    auto& dnf_group_predicates_ = prepared_dnf_group_predicates_;
    auto& dnf_group_predicates_per_channel_ = prepared_dnf_group_predicates_per_channel_;
    auto& dnf_group_or_ids_ = prepared_dnf_group_or_ids_;

    auto plain_snapshot = prepared_plain_snapshot_;
    if (!plain_snapshot) {
        throw std::runtime_error("FheFilter: input table lacks plain snapshot");
    }

    auto plain_copy = std::make_shared<PlainColumnTable>(*plain_snapshot);
    // Use "dummy_tag" as indicator name to integrate with dummy_tag column
    std::string dummy_tag_name = "dummy_tag";
    auto output = std::make_shared<FheColumnTable>(plain_copy, std::unordered_set<std::string>{});
    
    // Copy bin metadata from input to output (filter preserves group structure)
    if (input_->hasBinMetadata()) {
        output->setBinMetadata(input_->getBinMetadata(), input_->getBinGroupByOrdinals());
    }

    FheManager& manager = FheManager::getInstance();
    auto cc = manager.getComparisonCryptoContext();
    auto pk = manager.getComparisonPublicKey();
    size_t pack_slots = manager.getBFVComparisonBatchSize();
    size_t row_count = plain_copy->getRowCount();
    size_t chunk_count = (row_count + pack_slots - 1) / pack_slots;

    // ── QueryPlan/Filter: compute and apply optimal thread count (v3) ──
    int optimal_T_filter = omp_get_max_threads();  // fallback = current
    {
        const auto& plan = vaultdb::getCurrentQueryPlan();
        const vaultdb::ServerProfile& sp = vaultdb::globalServerProfile();
        bool has_dnf = !dnf_groups_.empty();
        size_t num_rns_ch = !predicates_per_channel_.empty()
            ? predicates_per_channel_.size() : 1;
        size_t work_items = chunk_count * num_rns_ch;

        // Always log hardware info (needed by calibrate_server.py)
        int phys = sp.is_loaded ? sp.physical_cores : readPhysicalCores();
        int logi = sp.is_loaded ? sp.logical_cores  : readLogicalCores();
        size_t l3 = sp.is_loaded ? sp.l3_cache_bytes : readL3CacheSize();
        std::cout << "[QueryPlan/Filter] server: physical=" << phys
                  << " logical=" << logi
                  << " l3=" << (l3 / (1024 * 1024)) << "MB" << std::endl;

        std::cout << "[QueryPlan/Filter] query: chunks=" << chunk_count
                  << " work_items=" << work_items
                  << " has_dnf=" << (has_dnf ? "true" : "false")
                  << std::endl;

        if (sp.is_loaded) {
            optimal_T_filter = vaultdb::selectThreadCount(
                work_items, has_dnf, plan.working_set_filter_bytes,
                phys, logi, l3);
            bool is_tiny = has_dnf || work_items < static_cast<size_t>(phys);
            double rho = (l3 > 0) ? static_cast<double>(plan.working_set_filter_bytes)
                                    / static_cast<double>(l3) : 2.0;
            vaultdb::logSmtDecision("Filter", optimal_T_filter, rho,
                plan.working_set_filter_bytes, l3, work_items, phys, is_tiny);
            // --fhe_force_threads override
            if (FLAGS_fhe_force_threads > 0) {
                std::cout << "[QueryPlan/Filter] OVERRIDE: T*=" << optimal_T_filter
                          << " -> T=" << FLAGS_fhe_force_threads << " (--fhe_force_threads)"
                          << std::endl;
                optimal_T_filter = FLAGS_fhe_force_threads;
            }
        } else {
            std::cout << "[QueryPlan/Filter] no profile loaded"
                      << " — using OMP_NUM_THREADS="
                      << omp_get_max_threads() << std::endl;
        }
    }
    // ── End QueryPlan/Filter ──

    vaultdb::ScopedOmpThreads scoped_filter_threads(optimal_T_filter);

    // Adaptive Parallelism: choose between chunk-level and OpenFHE internal parallelism.
    // NOTE: Predicate-level parallelism is intentionally disabled for stability.
    // OpenFHE comparator evaluation over shared contexts can throw inside OMP workers,
    // which manifests as "terminate called without an active exception".
    int max_threads = omp_get_max_threads();
    
    // Strategy:
    // 1. If we have many chunks, parallelize over chunks (Predicate loop runs serially inside).
    // 2. If we have few chunks but multiple predicates, parallelize over predicates.
    // 3. If we have few chunks and single predicate, use OpenFHE internal parallelism.
    bool use_chunk_parallelism = (chunk_count >= static_cast<size_t>(max_threads));
    bool use_predicate_parallelism = false;
    
    if (use_chunk_parallelism) {
        // Case 1: Many chunks -> High level parallelism on chunks
        omp_set_max_active_levels(1); // Disable OpenFHE internal parallelism
    } else {
        // Few chunks: keep predicate loop serial and let OpenFHE handle internal parallelism.
        omp_set_max_active_levels(max_threads);
    }

    // Get existing dummy_tag column from input (if encrypted)
    std::shared_ptr<FheColumn> existing_dummy_tag = input_->getFheColumn(dummy_tag_name);
    
    // Create dummy_tag column for output
    auto dummy_tag_column = std::make_shared<FheColumn>(dummy_tag_name);
    
    // When Aggregate uses RNS for SUM, it multiplies value ciphertexts (per channel) by (1 - dummy_tag).
    // EvalMult requires same modulus, so dummy_tag must be produced for every RNS channel.
    bool use_multi_channel = !predicates_per_channel_.empty();
    std::vector<Ciphertext<DCRTPoly>> ones_cipher_rns;
    ScopedPerfCacheMissCounter perf_cache_miss_counter("FheFilter");
    perf_cache_miss_counter.start();

    if (use_multi_channel) {
        size_t num_ch = predicates_per_channel_.size();
        ones_cipher_rns.resize(num_ch);
        for (size_t ch = 0; ch < num_ch; ++ch) {
            auto cc_ch = manager.getRnsContext(ch);
            auto pk_ch = manager.getRnsKeyPair(ch).publicKey;
            auto ones_rns_pt = cachedUniformPt(cc_ch, 1, pack_slots);
            ones_cipher_rns[ch] = cc_ch->Encrypt(pk_ch, ones_rns_pt);
        }
    }
    
    // Cached ones_cipher (FheManager reuses across runs) for single-channel
    Ciphertext<DCRTPoly> ones_cipher_shared = FheManager::getInstance().getOnesCipher(pack_slots);
    
    // Store results for each chunk (parallel processing)
    std::vector<std::shared_ptr<FheColumnChunk>> chunk_results(chunk_count);
    
    if (use_multi_channel) {
        // Multi-channel dummy_tag: warm up OpenFHE paths before parallel region to reduce lazy-init races.
        size_t num_ch = predicates_per_channel_.size();
        std::vector<ChannelOpStats> channel_stats(num_ch);
        std::vector<ChannelLatencyStats> latency_stats(num_ch);
        size_t rss_before = Utilities::residentMemoryUtilization(false);
        for (size_t ch = 0; ch < num_ch; ++ch) {
            auto cc_ch = manager.getRnsContext(ch);
            auto warmup = cc_ch->EvalMultAndRelinearize(ones_cipher_rns[ch], ones_cipher_rns[ch]);
            (void)warmup;
            channel_stats[ch].multCtCt();
            channel_stats[ch].relin();
            channel_stats[ch].keyswitch();
            channel_stats[ch].modreduce();
        }

        // Cache-aware batch scheduling: process chunks in batches sized to
        // keep the active ciphertext working set within L3 cache.
        std::vector<std::vector<Ciphertext<DCRTPoly>>> temp_ciphers(
            chunk_count, std::vector<Ciphertext<DCRTPoly>>(num_ch));

        const size_t ring_dim = manager.getBFVRingDim();
        const size_t max_limbs = getTowerCount(manager.getRnsContext(0));
        const size_t ct_size_bytes = ring_dim * max_limbs * 8 * 2; // 2 polys per ct
        const size_t l3_bytes = readL3CacheSize();  // per-CCX L3 on AMD, unified on Intel
        const int num_threads = omp_get_max_threads();

        // Target: per-thread working set <= per-CCX L3.
        // Each thread processes roughly (batch_size * num_ch) / num_threads work items.
        // Each work item holds 1 ciphertext of ct_size_bytes.
        // Constraint: (batch_size * num_ch / num_threads) * ct_size_bytes <= l3_bytes
        // => batch_size <= l3_bytes * num_threads / (num_ch * ct_size_bytes)
        size_t batch_size;
        if (num_ch > 0 && ct_size_bytes > 0 && num_threads > 0) {
            batch_size = (l3_bytes * static_cast<size_t>(num_threads))
                       / (num_ch * ct_size_bytes);
        } else {
            batch_size = chunk_count;
        }
        if (batch_size == 0) batch_size = 1;
        if (batch_size > chunk_count) batch_size = chunk_count;

        // Keep all threads busy: need at least num_threads work items per batch.
        // If batch would be too small to saturate threads, fall back to full dispatch
        // (better parallelism than strict cache locality).
        if (batch_size * num_ch < static_cast<size_t>(num_threads)) {
            batch_size = chunk_count;
        }

        // single unified log — printed after all adjustments
        double per_thread_ws_mb =
            (static_cast<double>(batch_size) * num_ch * ct_size_bytes)
            / static_cast<double>(num_threads) / (1024.0 * 1024.0);
        std::cout << "[FheFilter][CacheBatch]"
                  << " ct_size_mb=" << (ct_size_bytes / 1024.0 / 1024.0)
                  << " l3_mb=" << (l3_bytes / 1024.0 / 1024.0)
                  << " threads=" << num_threads
                  << " per_thread_ws_mb=" << per_thread_ws_mb
                  << " effective_batch=" << batch_size
                  << " chunk_count=" << chunk_count
                  << (batch_size == chunk_count ? " (full dispatch)"
                                                : " (cache-aware batching active)")
                  << std::endl;

        for (size_t batch_start = 0; batch_start < chunk_count; batch_start += batch_size) {
            size_t batch_end = std::min(batch_start + batch_size, chunk_count);
            size_t batch_work = (batch_end - batch_start) * num_ch;

            #pragma omp parallel for schedule(dynamic)
            for (size_t work_idx = 0; work_idx < batch_work; ++work_idx) {
                size_t local_chunk = work_idx / num_ch;
                size_t ch = work_idx % num_ch;
                size_t chunk_idx = batch_start + local_chunk;
                auto cc_ch = manager.getRnsContext(ch);
                auto pk_ch = manager.getRnsKeyPair(ch).publicKey;
                auto t0 = std::chrono::high_resolution_clock::now();
                temp_ciphers[chunk_idx][ch] = processChunkForFilterChannel(
                    chunk_idx, ch, predicates_per_channel_[ch], input_, plain_snapshot,
                    existing_dummy_tag, pack_slots, row_count, dummy_tag_name,
                    cc_ch, pk_ch, ones_cipher_rns[ch], &channel_stats[ch],
                    or_group_ids_);
                auto t1 = std::chrono::high_resolution_clock::now();
                uint64_t ns = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
                latency_stats[ch].record(ns);
            }
        }

        QuantizationParams chunk_params{};
        chunk_params.simdSlots = static_cast<unsigned int>(pack_slots);
        FheTypeDescriptor chunk_desc(FheDataType::BOOLEAN, FheEncodingType::BFV_PACKED_ENCODING);
        #pragma omp parallel for schedule(static)
        for (size_t chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx) {
            size_t effective_count = std::min(pack_slots, row_count - chunk_idx * pack_slots);
            chunk_results[chunk_idx] = std::make_shared<FheColumnChunk>(
                std::move(temp_ciphers[chunk_idx]), chunk_params, chunk_desc, effective_count);
        }
        size_t rss_after = Utilities::residentMemoryUtilization(false);
        printChannelOpStats(channel_stats, "FheFilter");

        // Memory-bound validation metrics (for 60K vs 600K analysis):
        // 1) per-ciphertext latency (avg/max), 2) total limb operations (TLO),
        // 3) estimated memory traffic, 4) RSS delta around filter execution.
        uint64_t total_tlo = 0;
        long double estimated_traffic_bytes = 0.0L;
        for (size_t ch = 0; ch < num_ch; ++ch) {
            uint64_t cnt = latency_stats[ch].chunk_count.load(std::memory_order_relaxed);
            uint64_t sum_ns = latency_stats[ch].sum_ns.load(std::memory_order_relaxed);
            uint64_t max_ns = latency_stats[ch].max_ns.load(std::memory_order_relaxed);
            double avg_ms = (cnt == 0) ? 0.0 : (static_cast<double>(sum_ns) / static_cast<double>(cnt)) / 1e6;
            double max_ms = static_cast<double>(max_ns) / 1e6;
            size_t limbs = getTowerCount(manager.getRnsContext(ch));

            uint64_t tlo_ch = cnt * static_cast<uint64_t>(limbs);
            total_tlo += tlo_ch;
            estimated_traffic_bytes += static_cast<long double>(cnt) *
                                       static_cast<long double>(limbs) *
                                       static_cast<long double>(manager.getBFVRingDim()) *
                                       8.0L;

            std::cout << "[FheFilter][Perf] ch=" << ch
                      << " chunks=" << cnt
                      << " chunk_avg_ms=" << avg_ms
                      << " chunk_max_ms=" << max_ms
                      << " limbs=" << limbs
                      << " TLO_ch=" << tlo_ch
                      << std::endl;
        }
        double est_traffic_gb = static_cast<double>(estimated_traffic_bytes / (1024.0L * 1024.0L * 1024.0L));
        long long rss_delta = static_cast<long long>(rss_after) - static_cast<long long>(rss_before);
        std::cout << "[FheFilter][Perf] total_chunks=" << (chunk_count * num_ch)
                  << " total_TLO=" << total_tlo
                  << " est_mem_traffic_gb=" << est_traffic_gb
                  << " rss_before=" << rss_before
                  << " rss_after=" << rss_after
                  << " rss_delta=" << rss_delta
                  << std::endl;
    } else if (use_chunk_parallelism) {
        #pragma omp parallel for schedule(dynamic)
        for (size_t chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx) {
            processChunkForFilter(chunk_idx, predicates_, input_, plain_snapshot, 
                                 existing_dummy_tag, cc, pk, ones_cipher_shared, 
                                 pack_slots, row_count, dummy_tag_name, chunk_results, false,
                                 or_group_ids_);
        }
    } else {
        for (size_t chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx) {
            processChunkForFilter(chunk_idx, predicates_, input_, plain_snapshot, 
                                 existing_dummy_tag, cc, pk, ones_cipher_shared, 
                                 pack_slots, row_count, dummy_tag_name, chunk_results,
                                 use_predicate_parallelism, or_group_ids_);
        }
    }

    perf_cache_miss_counter.stopAndPrint();

    // DNF evaluation: for each chunk, evaluate each DNF group, OR across groups, AND with main result.
    if (!dnf_group_predicates_.empty()) {
        if (FLAGS_debug) std::cout << "[FheFilter] DNF: evaluating " << dnf_group_predicates_.size()
                  << " OR-groups across " << chunk_count << " chunks" << std::endl;

        // Helper lambda: evaluate DNF groups for one channel (or comparison context).
        // Returns the OR'd result across all groups.
        auto evaluateDnfForChannel = [&](size_t chunk_idx,
                                         const std::vector<std::vector<SIMDFheGenericExpression>>& grp_preds_all,
                                         const CryptoContext<DCRTPoly>& eval_cc,
                                         size_t cipher_idx) -> Ciphertext<DCRTPoly> {
            Ciphertext<DCRTPoly> dnf_or_result;
            bool first_group = true;
            for (size_t g = 0; g < grp_preds_all.size(); ++g) {
                const auto& grp_preds = grp_preds_all[g];
                const auto& grp_or_ids = dnf_group_or_ids_[g];

                std::vector<Ciphertext<DCRTPoly>> pred_results(grp_preds.size());
                for (size_t i = 0; i < grp_preds.size(); ++i) {
                    auto chunk = grp_preds[i].call(input_.get(), chunk_idx);
                    if (!chunk) throw std::runtime_error("FheFilter: DNF predicate returned null chunk");
                    pred_results[i] = chunk->getCiphertext(cipher_idx);
                }

                // Phase 1: OR collapse (IN predicates within group)
                std::vector<Ciphertext<DCRTPoly>> and_operands;
                if (!grp_or_ids.empty()) {
                    std::map<int, Ciphertext<DCRTPoly>> group_results;
                    for (size_t i = 0; i < pred_results.size(); ++i) {
                        int gid = grp_or_ids[i];
                        auto it = group_results.find(gid);
                        if (it == group_results.end())
                            group_results[gid] = pred_results[i];
                        else
                            it->second = eval_cc->EvalAdd(it->second, pred_results[i]);
                    }
                    and_operands.reserve(group_results.size());
                    for (auto& [gid, cipher] : group_results) and_operands.push_back(std::move(cipher));
                } else {
                    and_operands = std::move(pred_results);
                }

                // Phase 2: AND tree reduction
                while (and_operands.size() > 1) {
                    std::vector<Ciphertext<DCRTPoly>> next;
                    next.reserve((and_operands.size() + 1) / 2);
                    for (size_t i = 0; i < and_operands.size(); i += 2) {
                        if (i + 1 < and_operands.size())
                            next.push_back(eval_cc->EvalMultAndRelinearize(and_operands[i], and_operands[i + 1]));
                        else
                            next.push_back(and_operands[i]);
                    }
                    and_operands = std::move(next);
                }

                if (first_group) {
                    dnf_or_result = and_operands[0];
                    first_group = false;
                } else {
                    dnf_or_result = eval_cc->EvalAdd(dnf_or_result, and_operands[0]);
                }
            }
            return dnf_or_result;
        };

        if (use_multi_channel && !dnf_group_predicates_per_channel_.empty() &&
            !dnf_group_predicates_per_channel_[0].empty()) {
            // Multi-channel: evaluate DNF per channel to preserve all RNS channels
            size_t num_ch = predicates_per_channel_.size();
            size_t dnf_total_work = chunk_count * num_ch;

            // Adaptive: parallelize outer loop only when enough chunks to fill threads;
            // otherwise let OpenFHE use internal parallelism (better for SF150, chunks=1).
            bool dnf_use_outer_parallel = (chunk_count >= static_cast<size_t>(omp_get_max_threads()));
            if (dnf_use_outer_parallel) {
                omp_set_max_active_levels(1);
            } else {
                omp_set_max_active_levels(2);
            }

            // Temp array: [chunk_count][num_ch] for parallel writes
            std::vector<std::vector<Ciphertext<DCRTPoly>>> temp_dnf(
                chunk_count, std::vector<Ciphertext<DCRTPoly>>(num_ch));

            #pragma omp parallel for schedule(dynamic) if(dnf_use_outer_parallel)
            for (size_t work_idx = 0; work_idx < dnf_total_work; ++work_idx) {
                size_t chunk_idx = work_idx / num_ch;
                size_t ch = work_idx % num_ch;
                if (!chunk_results[chunk_idx]) continue;
                auto cc_ch = manager.getRnsContext(ch);
                // Build per-channel view: dnf_group_predicates_per_channel_[g][ch] -> grp_preds_for_ch[g]
                std::vector<std::vector<SIMDFheGenericExpression>> grp_preds_for_ch(dnf_group_predicates_per_channel_.size());
                for (size_t g = 0; g < dnf_group_predicates_per_channel_.size(); ++g) {
                    grp_preds_for_ch[g] = dnf_group_predicates_per_channel_[g][ch];
                }
                auto dnf_or = evaluateDnfForChannel(chunk_idx, grp_preds_for_ch, cc_ch, 0);
                auto main_ct = chunk_results[chunk_idx]->getCiphertext(ch);
                temp_dnf[chunk_idx][ch] = cc_ch->EvalMultAndRelinearize(main_ct, dnf_or);
            }

            // Sequentially combine temp results into chunk_results
            for (size_t chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx) {
                if (!chunk_results[chunk_idx]) continue;
                auto params = chunk_results[chunk_idx]->q_params();
                auto desc = chunk_results[chunk_idx]->type_desc;
                auto cnt = chunk_results[chunk_idx]->packed_count;
                chunk_results[chunk_idx] = std::make_shared<FheColumnChunk>(
                    std::move(temp_dnf[chunk_idx]), params, desc, cnt);
            }
        } else {
            // Single-channel: use comparison-context DNF predicates
            bool dnf_use_outer_parallel_sc = (chunk_count >= static_cast<size_t>(omp_get_max_threads()));
            if (dnf_use_outer_parallel_sc) {
                omp_set_max_active_levels(1);
            } else {
                omp_set_max_active_levels(2);
            }
            #pragma omp parallel for schedule(dynamic) if(dnf_use_outer_parallel_sc)
            for (size_t chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx) {
                if (!chunk_results[chunk_idx]) continue;
                auto dnf_or = evaluateDnfForChannel(chunk_idx, dnf_group_predicates_, cc, 0);
                auto main_ct = chunk_results[chunk_idx]->getCiphertext();
                auto combined = cc->EvalMultAndRelinearize(main_ct, dnf_or);
                auto params = chunk_results[chunk_idx]->q_params();
                auto desc = chunk_results[chunk_idx]->type_desc;
                auto cnt = chunk_results[chunk_idx]->packed_count;
                chunk_results[chunk_idx] = std::make_shared<FheColumnChunk>(combined, params, desc, cnt);
            }
        }

        std::cout << "[FheFilter][DNF] chunks=" << chunk_count
                  << " groups=" << dnf_group_predicates_.size()
                  << " parallel=true" << std::endl;
        if (FLAGS_debug) std::cout << "[FheFilter] DNF: evaluation complete" << std::endl;
    }

    // Sequentially add chunks to column (thread-safe, fast)
    for (size_t chunk_idx = 0; chunk_idx < chunk_count; ++chunk_idx) {
        if (chunk_results[chunk_idx]) {
            dummy_tag_column->addFheChunk(chunk_results[chunk_idx]);
        }
    }

    // Add dummy_tag column to output and set as indicator
    output->addColumn(dummy_tag_column);
    output->setDummyTagColumn(dummy_tag_column);
    this->output_ = output;
    endTiming();
    printTiming();
    return this->output_;
}

OperatorType FheFilter::getType() const {
    return OperatorType::FHE_FILTER;
}

std::string FheFilter::getParameters() const {
    if (predicates_.empty()) {
        return "no_predicate";
    }
    std::string result;
    for (size_t i = 0; i < predicates_.size(); ++i) {
        if (i > 0) {
            result += " AND ";
        }
        result += predicates_[i].toString();
    }
    return result;
}

SIMDFheGenericExpression makePolynomialLessEqualPredicate(const QuerySchema& schema,
                                                          const std::string& column_name,
                                                          const std::vector<Ciphertext<DCRTPoly>>& threshold_digits,
                                                          size_t radix_base,
                                                          size_t rns_channel) {
    size_t num_digits = threshold_digits.size();
    if (num_digits == 0) {
        throw std::invalid_argument("makePolynomialLessEqualPredicate: threshold digits vector is empty");
    }
    QueryFieldDesc field_desc = schema.getField(column_name);
    auto node = std::make_shared<BFVRadixComparisonNode>(field_desc,
                                                        column_name,
                                                        threshold_digits,
                                                        FheFilterStyle::PolynomialLE,
                                                        radix_base,
                                                        num_digits,
                                                        rns_channel);
    return SIMDFheGenericExpression(node, column_name + "_poly_le", FieldType::BOOL);
}

SIMDFheGenericExpression makePolynomialLessThanPredicate(const QuerySchema& schema,
                                                         const std::string& column_name,
                                                         const std::vector<Ciphertext<DCRTPoly>>& threshold_digits,
                                                         size_t radix_base,
                                                         size_t rns_channel) {
    size_t num_digits = threshold_digits.size();
    if (num_digits == 0) {
        throw std::invalid_argument("makePolynomialLessThanPredicate: threshold digits vector is empty");
    }
    QueryFieldDesc field_desc = schema.getField(column_name);
    auto node = std::make_shared<BFVRadixComparisonNode>(field_desc,
                                                         column_name,
                                                         threshold_digits,
                                                         FheFilterStyle::PolynomialLT,
                                                         radix_base,
                                                         num_digits,
                                                         rns_channel);
    return SIMDFheGenericExpression(node, column_name + "_poly_lt", FieldType::BOOL);
}

SIMDFheGenericExpression makePolynomialGreaterEqualPredicate(const QuerySchema& schema,
                                                             const std::string& column_name,
                                                             const std::vector<Ciphertext<DCRTPoly>>& threshold_digits,
                                                             size_t radix_base,
                                                             size_t rns_channel) {
    size_t num_digits = threshold_digits.size();
    if (num_digits == 0) {
        throw std::invalid_argument("makePolynomialGreaterEqualPredicate: threshold digits vector is empty");
    }
    QueryFieldDesc field_desc = schema.getField(column_name);
    auto node = std::make_shared<BFVRadixComparisonNode>(field_desc,
                                                         column_name,
                                                         threshold_digits,
                                                         FheFilterStyle::PolynomialGE,
                                                         radix_base,
                                                         num_digits,
                                                         rns_channel);
    return SIMDFheGenericExpression(node, column_name + "_poly_ge", FieldType::BOOL);
}

SIMDFheGenericExpression makePolynomialGreaterThanPredicate(const QuerySchema& schema,
                                                            const std::string& column_name,
                                                            const std::vector<Ciphertext<DCRTPoly>>& threshold_digits,
                                                            size_t radix_base,
                                                            size_t rns_channel) {
    size_t num_digits = threshold_digits.size();
    if (num_digits == 0) {
        throw std::invalid_argument("makePolynomialGreaterThanPredicate: threshold digits vector is empty");
    }
    QueryFieldDesc field_desc = schema.getField(column_name);
    auto node = std::make_shared<BFVRadixComparisonNode>(field_desc,
                                                        column_name,
                                                        threshold_digits,
                                                        FheFilterStyle::PolynomialGT,
                                                        radix_base,
                                                        num_digits,
                                                        rns_channel);
    return SIMDFheGenericExpression(node, column_name + "_poly_gt", FieldType::BOOL);
}

SIMDFheGenericExpression makePolynomialEqualPredicate(const QuerySchema& schema,
                                                      const std::string& column_name,
                                                      const std::vector<Ciphertext<DCRTPoly>>& threshold_digits,
                                                      size_t radix_base,
                                                      size_t rns_channel) {
    size_t num_digits = threshold_digits.size();
    if (num_digits == 0) {
        throw std::invalid_argument("makePolynomialEqualPredicate: threshold digits vector is empty");
    }
    QueryFieldDesc field_desc = schema.getField(column_name);
    auto node = std::make_shared<BFVRadixComparisonNode>(field_desc,
                                                        column_name,
                                                        threshold_digits,
                                                        FheFilterStyle::PolynomialEQ,
                                                        radix_base,
                                                        num_digits,
                                                        rns_channel);
    return SIMDFheGenericExpression(node, column_name + "_poly_eq", FieldType::BOOL);
}

ComparisonStats getPolynomialComparisonStats() {
    std::lock_guard<std::mutex> lock(poly_stats_mutex);
    return poly_stats;
}

void resetComparisonStats() {
    resetStats();
}

void setComparatorStatsEnabled(bool enabled) {
    g_comparator_stats_enabled = enabled;
}

bool isComparatorStatsEnabled() {
    return g_comparator_stats_enabled;
}

void printComparatorStats(const ComparisonStats& stats, const char* label) {
    std::cout << "[CmpStats " << (label ? label : "Comparator") << "] "
              << "EvalMult=" << stats.eval_mult_count
              << " EvalAdd=" << stats.eval_add_count
              << " EvalSub=" << stats.eval_sub_count
              << " Rotate=" << stats.eval_rotate_count
              << " Relin=" << stats.relinearize_count
              << " Rescale=" << stats.rescale_count
              << " Ciphertext=" << stats.ciphertext_count
              << " DigitCompareCalls=" << stats.digit_compare_call_count
              << " PolyEvalGT=" << stats.poly_eval_gt_count
              << " PolyEvalLT=" << stats.poly_eval_lt_count
              << std::endl;
}

} // namespace vaultdb
