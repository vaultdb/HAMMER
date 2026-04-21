#pragma once

#include <iostream>
#include <fstream>
#include <string>

#if defined(__linux__)
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace vaultdb {

#if defined(__linux__)

    // Detect stall_mem RAW event config based on CPU microarchitecture.
    // Sapphire Rapids / Ice Lake → 0x05A3 (cycle_activity.stalls_l3_miss)
    // Ivy Bridge / Haswell       → 0x14A3 (cycle_activity.stalls_mem_any)
    static inline uint32_t detectStallMemConfig() {
        std::ifstream f("/proc/cpuinfo");
        std::string line;
        while (std::getline(f, line)) {
            if (line.find("model name") == std::string::npos) continue;
            if (line.find("Sapphire") != std::string::npos ||
                line.find("Ice Lake") != std::string::npos)
                return 0x05A3;
            if (line.find("Ivy Bridge")  != std::string::npos ||
                line.find("Xeon E5")     != std::string::npos ||
                line.find("i7-3")        != std::string::npos)
                return 0x14A3;
            return 0x14A3;  // default: try stalls_mem_any
        }
        return 0x14A3;
    }

    class ScopedPerfCacheMissCounter {
    public:
        explicit ScopedPerfCacheMissCounter(const char* label)
            : label_(label ? label : "FheFilter") {

            auto open_counter = [](uint32_t type, uint64_t config) -> int {
                struct perf_event_attr pe{};
                pe.type           = type;
                pe.size           = sizeof(pe);
                pe.config         = config;
                pe.disabled       = 1;
                pe.exclude_kernel = 1;
                pe.exclude_hv     = 1;
                return static_cast<int>(
                    syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0));
            };

            fd_llc_miss_  = open_counter(PERF_TYPE_HARDWARE,
                                         PERF_COUNT_HW_CACHE_MISSES);
            fd_llc_ref_   = open_counter(PERF_TYPE_HARDWARE,
                                         PERF_COUNT_HW_CACHE_REFERENCES);
            fd_inst_      = open_counter(PERF_TYPE_HARDWARE,
                                         PERF_COUNT_HW_INSTRUCTIONS);
            fd_cycles_    = open_counter(PERF_TYPE_HARDWARE,
                                         PERF_COUNT_HW_CPU_CYCLES);

            available_ = (fd_llc_miss_ != -1 && fd_llc_ref_ != -1 &&
                          fd_inst_     != -1 && fd_cycles_  != -1);

            // RAW events for HT contention analysis
            uint32_t stall_cfg = detectStallMemConfig();
            fd_stall_mem_ = open_counter(PERF_TYPE_RAW, stall_cfg);
            if (fd_stall_mem_ == -1)
                std::cerr << "[PerfStats] stall_mem fd open failed (config=0x"
                          << std::hex << stall_cfg << std::dec << ")\n";

            fd_l3_miss_load_ = open_counter(PERF_TYPE_RAW, 0x20D1);  // mem_load_retired.l3_miss
            if (fd_l3_miss_load_ == -1)
                std::cerr << "[PerfStats] l3_miss_load fd open failed\n";
        }

        ~ScopedPerfCacheMissCounter() {
            for (int fd : {fd_llc_miss_, fd_llc_ref_, fd_inst_, fd_cycles_,
                           fd_stall_mem_, fd_l3_miss_load_})
                if (fd != -1) close(fd);
        }

        void start() {
            if (!available_) return;
            for (int fd : {fd_llc_miss_, fd_llc_ref_, fd_inst_, fd_cycles_,
                           fd_stall_mem_, fd_l3_miss_load_}) {
                if (fd != -1) {
                    ioctl(fd, PERF_EVENT_IOC_RESET,  0);
                    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
                }
            }
            running_ = true;
        }

        void stopAndPrint() {
            if (!available_ || !running_) return;
            for (int fd : {fd_llc_miss_, fd_llc_ref_, fd_inst_, fd_cycles_,
                           fd_stall_mem_, fd_l3_miss_load_}) {
                if (fd != -1)
                    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
            }

            auto read_counter = [](int fd) -> long long {
                long long val = 0;
                if (fd != -1)
                    read(fd, &val, sizeof(val));
                return val;
            };

            long long llc_miss  = read_counter(fd_llc_miss_);
            long long llc_ref   = read_counter(fd_llc_ref_);
            long long inst      = read_counter(fd_inst_);
            long long cycles    = read_counter(fd_cycles_);

            long long stall_mem    = read_counter(fd_stall_mem_);
            long long l3_miss_load = read_counter(fd_l3_miss_load_);

            double miss_rate = (llc_ref > 0)
                ? static_cast<double>(llc_miss) / static_cast<double>(llc_ref)
                : 0.0;
            double ipc = (cycles > 0)
                ? static_cast<double>(inst) / static_cast<double>(cycles)
                : 0.0;
            double stall_frac = (cycles > 0)
                ? static_cast<double>(stall_mem) / static_cast<double>(cycles)
                : 0.0;

            std::cout << "[PerfStats " << label_ << "]"
                      << " LLC_miss="       << llc_miss
                      << " LLC_ref="        << llc_ref
                      << " LLC_miss_rate="  << miss_rate
                      << " instructions="   << inst
                      << " cycles="         << cycles
                      << " IPC="            << ipc
                      << " stall_mem="      << stall_mem
                      << " stall_mem_frac=" << stall_frac
                      << " l3_miss_load="   << l3_miss_load
                      << std::endl;
            running_ = false;
        }

    private:
        const char* label_;
        int fd_llc_miss_ = -1;
        int fd_llc_ref_  = -1;
        int fd_inst_     = -1;
        int fd_cycles_   = -1;
        int fd_stall_mem_    = -1;
        int fd_l3_miss_load_ = -1;
        bool available_  = false;
        bool running_    = false;
    };
#else
    class ScopedPerfCacheMissCounter {
    public:
        explicit ScopedPerfCacheMissCounter(const char*) {}
        void start() {}
        void stopAndPrint() {}
    };
#endif

} // namespace vaultdb
