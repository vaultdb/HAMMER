#ifndef GPU_FHE_COLUMN_TABLE_CUH_
#define GPU_FHE_COLUMN_TABLE_CUH_

#include "gpu_fhe_column.cuh"
#include "gpu_fhe_bin_metadata.cuh"
#include <unordered_map>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstddef>

namespace vaultdb {

// GPU-resident BFV columnar table: a named collection of GpuFheColumn.
// BFV-only, flat (no base class), crypto lives in GpuFheBackend.
class GpuFheColumnTable {
public:
    GpuFheColumnTable() : row_count_(0) {}
    explicit GpuFheColumnTable(std::size_t row_count) : row_count_(row_count) {}

    // ----------------------------------------------------------------
    // Column management
    // ----------------------------------------------------------------
    void addColumn(GpuFheColumn column);
    bool hasColumn(const std::string& name) const;

    GpuFheColumn&       getColumn(const std::string& name);
    const GpuFheColumn& getColumn(const std::string& name) const;

    std::vector<std::string> getColumnNames() const;
    std::size_t numColumns() const { return columns_.size(); }

    // ----------------------------------------------------------------
    // Row count
    // ----------------------------------------------------------------
    std::size_t getRowCount() const { return row_count_; }
    void setRowCount(std::size_t n) { row_count_ = n; }

    // ----------------------------------------------------------------
    // Bin metadata (per-group layout info for aggregation/group-by).
    // Mirrors CPU FheColumnTable::getBinMetadata() / setBinMetadata().
    // ----------------------------------------------------------------
    void setBinMetadata(std::vector<GpuBinGroupMetadata> m) {
        bin_metadata_ = std::move(m);
    }
    const std::vector<GpuBinGroupMetadata>& getBinMetadata() const {
        return bin_metadata_;
    }

private:
    std::unordered_map<std::string, GpuFheColumn> columns_;
    std::size_t row_count_;
    std::vector<GpuBinGroupMetadata> bin_metadata_;
};

} // namespace vaultdb

#endif // GPU_FHE_COLUMN_TABLE_CUH_
