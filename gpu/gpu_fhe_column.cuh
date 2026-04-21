#ifndef GPU_FHE_COLUMN_CUH_
#define GPU_FHE_COLUMN_CUH_

#include "fhe_column_chunk.cuh"
#include <string>
#include <vector>
#include <stdexcept>
#include <cstddef>
#include <utility>

namespace vaultdb {

// GPU-resident BFV column: a named sequence of GpuFheColumnChunk.
// BFV-only, no base-class hierarchy, no FheTypeBase.
class GpuFheColumn {
public:
    GpuFheColumn() = default;
    explicit GpuFheColumn(std::string name) : name_(std::move(name)) {}

    void addChunk(GpuFheColumnChunk chunk) {
        chunks_.push_back(std::move(chunk));
    }

    const std::string& getName() const { return name_; }

    std::size_t getRowCount() const {
        std::size_t total = 0;
        for (const auto& c : chunks_) {
            total += c.size();
        }
        return total;
    }

    std::size_t size() const { return chunks_.size(); }
    bool empty() const { return chunks_.empty(); }
    std::size_t getRnsLevel() const {
        return chunks_.empty() ? 1 : chunks_[0].getRnsLevel();
    }

    GpuFheColumnChunk& getChunk(std::size_t idx) {
        if (idx >= chunks_.size())
            throw std::out_of_range("GpuFheColumn::getChunk: index out of bounds");
        return chunks_[idx];
    }

    const GpuFheColumnChunk& getChunk(std::size_t idx) const {
        if (idx >= chunks_.size())
            throw std::out_of_range("GpuFheColumn::getChunk: index out of bounds");
        return chunks_[idx];
    }

    std::vector<GpuFheColumnChunk>& getChunks() { return chunks_; }
    const std::vector<GpuFheColumnChunk>& getChunks() const { return chunks_; }

private:
    std::string name_;
    std::vector<GpuFheColumnChunk> chunks_;
};

} // namespace vaultdb

#endif // GPU_FHE_COLUMN_CUH_
