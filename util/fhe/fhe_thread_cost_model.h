#pragma once

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <string>
#include <omp.h>

namespace vaultdb {

// ── ServerProfile ──
// Minimal profile: hardware topology only.  No calibration needed for T* decision.

struct ServerProfile {
    std::string hostname;
    int    physical_cores    = 6;
    int    logical_cores     = 12;
    size_t l3_cache_bytes    = 15ULL * 1024 * 1024;

    // Kept for documentation / appendix only (not used in T* decision)
    double pi_spill          = 2.0;    // HT penalty when DRAM-bound
    double gamma_spill       = 1.0;    // curve shape for spill regime
    double over_thread_alpha = 0.05;   // over-threading penalty rate

    bool is_loaded = false;  // false = using defaults
};

// ── JSON loader ──

// Loads server_profile_*.json.
// Only requires: hostname, physical_cores, logical_cores, l3_cache_bytes.
// Other fields are optional (for documentation/appendix).
inline ServerProfile loadServerProfile(const std::string& json_path) {
    ServerProfile p;
    if (json_path.empty()) return p;  // use defaults

    std::ifstream f(json_path);
    if (!f.is_open()) {
        std::cerr << "[ServerProfile] WARNING: cannot open " << json_path
                  << " — using default parameters" << std::endl;
        return p;
    }

    // Read entire file
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

    auto getInt = [&](const std::string& key, int def) -> int {
        std::regex re("\"" + key + "\"\\s*:\\s*(\\d+)");
        std::smatch m;
        if (std::regex_search(content, m, re))
            return std::stoi(m[1]);
        return def;
    };
    auto getDbl = [&](const std::string& key, double def) -> double {
        std::regex re("\"" + key + "\"\\s*:\\s*([\\d.eE+\\-]+)");
        std::smatch m;
        if (std::regex_search(content, m, re))
            return std::stod(m[1]);
        return def;
    };
    auto getStr = [&](const std::string& key, const std::string& def)
        -> std::string {
        std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch m;
        if (std::regex_search(content, m, re)) return m[1];
        return def;
    };

    p.hostname            = getStr("hostname",           "unknown");
    p.physical_cores      = getInt("physical_cores",     6);
    p.logical_cores       = getInt("logical_cores",      12);
    p.l3_cache_bytes      = static_cast<size_t>(
                              getInt("l3_cache_bytes",   15728640));

    // Optional: kept for documentation / appendix
    p.pi_spill            = getDbl("pi_spill",    getDbl("ht_pi_L", 2.0));
    p.gamma_spill         = getDbl("gamma_spill", getDbl("ht_gamma", 1.0));
    p.over_thread_alpha   = getDbl("over_thread_alpha",  0.05);

    p.is_loaded = true;

    std::cout << "[ServerProfile] Loaded: " << json_path << std::endl;
    std::cout << "[ServerProfile] P=" << p.physical_cores
              << " H=" << p.logical_cores
              << " L3=" << (p.l3_cache_bytes / (1024 * 1024)) << "MB"
              << std::endl;
    return p;
}

// Global singleton — loaded once at startup
inline ServerProfile& globalServerProfile() {
    static ServerProfile instance;
    return instance;
}

inline void initServerProfile(const std::string& json_path) {
    globalServerProfile() = loadServerProfile(json_path);
}

// ── ScopedOmpThreads ──

// RAII wrapper: sets OMP threads for a scope, restores on exit
class ScopedOmpThreads {
    int prev_;
    bool active_;
public:
    explicit ScopedOmpThreads(int n) : active_(n > 0) {
        if (active_) {
            prev_ = omp_get_max_threads();
            if (n != prev_) {
                omp_set_num_threads(n);
            } else {
                active_ = false;  // no change needed
            }
        }
    }
    ~ScopedOmpThreads() {
        if (active_) {
            omp_set_num_threads(prev_);
        }
    }
    // Non-copyable
    ScopedOmpThreads(const ScopedOmpThreads&) = delete;
    ScopedOmpThreads& operator=(const ScopedOmpThreads&) = delete;
};

} // namespace vaultdb
