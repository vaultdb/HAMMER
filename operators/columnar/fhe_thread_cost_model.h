#pragma once

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace vaultdb {

// ─── 1. ServerProfile ───────────────────────────────────────────────

struct ServerProfile {
    int    physical_cores;
    int    logical_cores;
    size_t l3_cache_bytes;
    double ht_penalty_max;   // chunk_avg(logical) / chunk_avg(physical)
    double ht_saturation_w;  // controls how fast penalty saturates
    double ms_per_unit;      // base cost per weighted_complexity unit
    std::string name;
};

inline ServerProfile coddProfile() {
    return {6, 12, 15ULL * 1024 * 1024, 1.75, 10.0, 8500.0, "codd"};
}

inline ServerProfile iitProfile() {
    return {16, 32, 45ULL * 1024 * 1024, 0.0, 15.0, 0.0, "iit"};
}

inline ServerProfile detectServerProfile() {
    ServerProfile sp{};
    sp.name = "auto";
    sp.ht_penalty_max = 0.0;
    sp.ht_saturation_w = 10.0;
    sp.ms_per_unit = 0.0;

    // Count logical cores and unique physical cores from /proc/cpuinfo
    int logical = 0;
    // Map physical_id -> set of core_ids (use vectors to avoid <set>/<map>)
    struct PhysCores {
        int phys_id;
        std::vector<int> core_ids;
    };
    std::vector<PhysCores> phys_map;
    int cur_phys_id = -1;

    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.rfind("processor", 0) == 0) {
                ++logical;
            } else if (line.rfind("physical id", 0) == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos)
                    cur_phys_id = std::stoi(line.substr(pos + 1));
            } else if (line.rfind("core id", 0) == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos) {
                    int cid = std::stoi(line.substr(pos + 1));
                    // Find or create entry for cur_phys_id
                    PhysCores* entry = nullptr;
                    for (auto& p : phys_map) {
                        if (p.phys_id == cur_phys_id) { entry = &p; break; }
                    }
                    if (!entry) {
                        phys_map.push_back({cur_phys_id, {}});
                        entry = &phys_map.back();
                    }
                    bool found = false;
                    for (int id : entry->core_ids) {
                        if (id == cid) { found = true; break; }
                    }
                    if (!found) entry->core_ids.push_back(cid);
                }
            }
        }
    }

    int physical = 0;
    for (const auto& p : phys_map)
        physical += static_cast<int>(p.core_ids.size());

    sp.logical_cores = (logical > 0) ? logical : 1;
    sp.physical_cores = (physical > 0) ? physical : sp.logical_cores;

    // Read L3 cache size from sysfs
    sp.l3_cache_bytes = 0;
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
        fsize >> sz_str;
        size_t val = std::stoull(sz_str);
        if (!sz_str.empty()) {
            char suffix = sz_str.back();
            if (suffix == 'K' || suffix == 'k') val *= 1024;
            else if (suffix == 'M' || suffix == 'm') val *= 1024 * 1024;
        }
        sp.l3_cache_bytes = val;
        break;
    }
    if (sp.l3_cache_bytes == 0)
        sp.l3_cache_bytes = 15ULL * 1024 * 1024; // 15 MB fallback

    return sp;
}

// ─── 2. Predicate complexity ────────────────────────────────────────

struct PredicateInfo {
    int  radix_base;
    int  num_digits;
    bool is_dnf;
};

inline int costWeight(int radix_base) {
    switch (radix_base) {
        case 4:  return 4;
        case 5:  return 5;
        case 7:  return 7;
        case 9:  return 9;
        default: return radix_base; // reasonable fallback
    }
}

inline double weightedComplexity(const std::vector<PredicateInfo>& predicates) {
    double wc = 0.0;
    for (const auto& p : predicates)
        wc += costWeight(p.radix_base) * p.num_digits;
    return wc;
}

// ─── 3. HT penalty curve ───────────────────────────────────────────

inline double htPenalty(int T, const ServerProfile& server) {
    int P = server.physical_cores;
    if (T <= P) return 1.0;
    double ht_ratio = static_cast<double>(T - P) / static_cast<double>(P);
    double saturation = server.ht_saturation_w;
    if (saturation <= 0.0) saturation = 10.0;
    return 1.0 + (server.ht_penalty_max - 1.0)
                 * (1.0 - std::exp(-ht_ratio * saturation));
}

// ─── 4. Core functions ─────────────────────────────────────────────

inline int optimalThreads(
    size_t rows,
    int    rns_channels,
    bool   has_dnf,
    const  ServerProfile& server)
{
    if (has_dnf) return server.physical_cores;

    const size_t pack_slots = 32768;
    size_t chunks = (rows + pack_slots - 1) / pack_slots;
    size_t work_items = chunks * static_cast<size_t>(rns_channels);

    int best_T = 1;
    double best_cost = std::numeric_limits<double>::max();

    for (int T = 1; T <= server.logical_cores; ++T) {
        double rounds = std::ceil(static_cast<double>(work_items) / T);
        double penalty = htPenalty(T, server);
        double cost = rounds * penalty;
        if (cost < best_cost) {
            best_cost = cost;
            best_T = T;
        }
    }
    return best_T;
}

inline size_t optimalBatchSize(
    int    optimal_T,
    int    rns_channels,
    size_t ct_size_bytes,
    const  ServerProfile& server)
{
    size_t denom = static_cast<size_t>(optimal_T)
                   * static_cast<size_t>(rns_channels)
                   * ct_size_bytes;
    if (denom == 0) return 1;
    size_t batch = server.l3_cache_bytes / denom;
    return (batch > 0) ? batch : 1;
}

// ─── 5. Calibration helpers ─────────────────────────────────────────

inline double calibrateMsPerUnit(double measured_chunk_avg_ms, double wc) {
    if (wc <= 0.0) return 0.0;
    return measured_chunk_avg_ms / wc;
}

inline double calibrateHtPenalty(
    double chunk_avg_physical,
    double chunk_avg_logical)
{
    if (chunk_avg_physical <= 0.0) return 0.0;
    return chunk_avg_logical / chunk_avg_physical;
}

// ─── 6. Validation / logging ────────────────────────────────────────

struct PredictionResult {
    std::string query;
    int         sf;
    int         predicted_T;
    int         actual_T;       // from sweep, -1 if unknown
    double      predicted_ms;
    double      actual_ms;      // -1 if unknown
    double      error_pct;      // abs(predicted-actual)/actual*100
    size_t      batch_size;
};

inline void printPredictions(
    const ServerProfile& server,
    const std::vector<PredictionResult>& results)
{
    std::cout << "\n=== Thread Cost Model Predictions (server: "
              << server.name << ") ===\n";
    std::cout << "  P=" << server.physical_cores
              << "  L=" << server.logical_cores
              << "  L3=" << (server.l3_cache_bytes / (1024.0 * 1024.0)) << " MB"
              << "  ht_penalty_max=" << server.ht_penalty_max
              << "  ms_per_unit=" << server.ms_per_unit << "\n\n";

    // Header
    std::ostringstream hdr;
    hdr << "  ";
    auto pad = [](const std::string& s, int w) {
        if (static_cast<int>(s.size()) >= w) return s;
        return s + std::string(w - static_cast<int>(s.size()), ' ');
    };
    hdr << pad("Query", 8)
        << pad("SF", 8)
        << pad("PredT", 8)
        << pad("ActT", 8)
        << pad("PredMs", 12)
        << pad("ActMs", 12)
        << pad("Err%", 10)
        << pad("Batch", 8);
    std::cout << hdr.str() << "\n";
    std::cout << "  " << std::string(74, '-') << "\n";

    for (const auto& r : results) {
        std::ostringstream row;
        row << "  ";
        row << pad(r.query, 8);
        row << pad(std::to_string(r.sf), 8);
        row << pad(std::to_string(r.predicted_T), 8);
        if (r.actual_T >= 0)
            row << pad(std::to_string(r.actual_T), 8);
        else
            row << pad("-", 8);

        std::ostringstream pred_ms;
        pred_ms.precision(1);
        pred_ms << std::fixed << r.predicted_ms;
        row << pad(pred_ms.str(), 12);

        if (r.actual_ms >= 0) {
            std::ostringstream act_ms;
            act_ms.precision(1);
            act_ms << std::fixed << r.actual_ms;
            row << pad(act_ms.str(), 12);
        } else {
            row << pad("-", 12);
        }

        if (r.actual_ms > 0 && r.actual_T >= 0) {
            std::ostringstream err;
            err.precision(1);
            err << std::fixed << r.error_pct << "%";
            row << pad(err.str(), 10);
        } else {
            row << pad("-", 10);
        }

        row << pad(std::to_string(r.batch_size), 8);
        std::cout << row.str() << "\n";
    }
    std::cout << std::endl;
}

} // namespace vaultdb
