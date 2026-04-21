#ifndef FHE_COLUMN_H_
#define FHE_COLUMN_H_

#include "fhe_column_chunk.h"
#include <query_table/columnar/column_base.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstddef>
#include <memory>
#include <numeric>
#include <algorithm>

namespace vaultdb {

    class FheColumn : public ColumnBase<void> {
    private:
        std::string m_column_name;
        std::vector<std::shared_ptr<FheColumnChunk>> m_chunks;
        /// Number of RNS channels (1 = single modulus; 2..N = multi-channel RNS). Set from first chunk.
        size_t rns_level_ = 1;

        std::size_t calculateRowCount() const {
            std::size_t total_rows = 0;
            for (const auto& chunk_ptr : m_chunks) {
                if (chunk_ptr) {
                    total_rows += chunk_ptr->size();
                }
            }
            return total_rows;
        }

    public:
        FheColumn() = default;
        explicit FheColumn(const std::string& name) : m_column_name(name) {}

        void addFheChunk(const std::shared_ptr<FheColumnChunk>& chunk) {
            if (chunk && m_chunks.empty()) {
                rns_level_ = chunk->getRnsLevel();
            }
            m_chunks.push_back(chunk);
        }

        // --- Overrides for ColumnBase<void> ---
        std::string getName() const override { return m_column_name; }
        std::size_t getRowCount() const override { return calculateRowCount(); }

        const std::vector<std::shared_ptr<ColumnChunkBase<void>>>& getChunks() const override {
            return reinterpret_cast<const std::vector<std::shared_ptr<ColumnChunkBase<void>>>&>(m_chunks);
        }

        // --- Other FheColumn specific methods ---
        const std::vector<std::shared_ptr<FheColumnChunk>>& getFheChunks() const {
            return m_chunks;
        }

        std::vector<std::shared_ptr<FheColumnChunk>>& getMutableFheChunks() {
            return m_chunks;
        }

        std::shared_ptr<ColumnChunkBase<void>> getChunk(size_t idx) const override {
            if (idx >= m_chunks.size()) {
                throw std::out_of_range("FheColumn::getChunk: index out of bounds.");
            }
            return reinterpret_cast<const std::shared_ptr<ColumnChunkBase<void>>&>(m_chunks[idx]);
        }

        std::shared_ptr<FheColumnChunk> getConcreteChunk(size_t idx) const {
            if (idx >= m_chunks.size()) {
                throw std::out_of_range("FheColumn::getConcreteChunk: index out of bounds.");
            }
            return m_chunks[idx];
        }

        /// Number of RNS channels (1 = single modulus; 2..N = multi-channel RNS). From first chunk or 1 if no chunks.
        size_t getRnsLevel() const {
            return m_chunks.empty() ? 1 : rns_level_;
        }

    };

} // namespace vaultdb

#endif // FHE_COLUMN_H_
