#ifndef _COLUMN_BASE_H_
#define _COLUMN_BASE_H_

// Standard library includes needed by ColumnBase, PlainColumn, and ColumnTableBase
#include <string>
#include <vector>
#include <memory>
#include <cstddef>
#include <numeric>           // For std::accumulate (used in PlainColumn::getRowCount, potentially)
#include <stdexcept>         // For std::runtime_error, std::out_of_range, std::invalid_argument

// Project-specific includes
#include "column_chunk_base.h"  // Defines ColumnChunkBase<B>
#include "plain_column_chunk.h" // Defines PlainColumnChunk (needed for PlainColumn)

namespace vaultdb {

    // --- ColumnBase Definition ---
    template<typename B>
    class ColumnBase {
    public:
        virtual ~ColumnBase() = default;
        virtual std::string getName() const = 0;
        virtual std::size_t getRowCount() const = 0;
        virtual const std::vector<std::shared_ptr<ColumnChunkBase<B>>>& getChunks() const = 0;
        virtual std::shared_ptr<ColumnChunkBase<B>> getChunk(size_t idx) const = 0;
    };


    // --- PlainColumn Definition (Derived from ColumnBase<bool>) ---
    class PlainColumn : public ColumnBase<bool> {
    private:
        std::string m_name;
        std::vector<std::shared_ptr<ColumnChunkBase<bool>>> m_chunks; // Stores base pointers to PlainColumnChunk
        bool isQuantized_ = false;

    public:
        explicit PlainColumn(const std::string& name) : m_name(name) {}

        void addChunk(const std::shared_ptr<PlainColumnChunk>& chunk) {
            if (chunk) {
                m_chunks.push_back(chunk); // Upcasting PlainColumnChunk to ColumnChunkBase<bool>
            }
        }

        std::string getName() const override {
            return m_name;
        }

        std::size_t getRowCount() const override {
            std::size_t total_rows = 0;
            for (const auto& chunk_ptr : m_chunks) {
                if (chunk_ptr) {
                    total_rows += chunk_ptr->size(); // size() is from ColumnChunkBase
                }
            }
            return total_rows;
        }

        const std::vector<std::shared_ptr<ColumnChunkBase<bool>>>& getChunks() const override {
            return m_chunks;
        }

        std::shared_ptr<PlainColumnChunk> getChunk(size_t idx) const override {
            if (idx >= m_chunks.size()) {
                throw std::out_of_range("PlainColumn::getChunk: chunk index out of bounds.");
            }
            auto chunk = std::dynamic_pointer_cast<PlainColumnChunk>(m_chunks[idx]);
            if (!chunk) {
                throw std::runtime_error("PlainColumn::getChunk: chunk is not a PlainColumnChunk.");
            }
            return chunk;
        }

        std::vector<std::shared_ptr<PlainColumnChunk>> getPlainChunks() const {
            std::vector<std::shared_ptr<PlainColumnChunk>> concrete_chunks;
            concrete_chunks.reserve(m_chunks.size());
            for (const auto& base_ptr : m_chunks) {
                auto concrete_chunk = std::dynamic_pointer_cast<PlainColumnChunk>(base_ptr);
                if (concrete_chunk) {
                    concrete_chunks.push_back(concrete_chunk);
                } else if (base_ptr != nullptr) {
                    throw std::runtime_error("PlainColumn::getPlainChunks: A chunk is not a PlainColumnChunk.");
                }
            }
            return concrete_chunks;
        }

        const void setIsQuantized(bool q) { isQuantized_ = q; }
        const bool isQuantized() const { return isQuantized_; }

        // Equality operator for PlainColumn
        bool operator==(const PlainColumn& other) const {
            if (this == &other) return true;
            if (m_name != other.m_name) return false;
            if (m_chunks.size() != other.m_chunks.size()) return false;
            if (getRowCount() != other.getRowCount()) return false; // Overall row count check

            // Compare chunks one by one
            // Assumes that m_chunks for PlainColumn only ever contain PlainColumnChunk (which is ColumnChunkBase<bool>)
            for (size_t i = 0; i < m_chunks.size(); ++i) {
                const auto& chunk_base_lhs = m_chunks[i];
                const auto& chunk_base_rhs = other.m_chunks[i];

                if (!chunk_base_lhs && !chunk_base_rhs) continue; // Both null is okay
                if (!chunk_base_lhs || !chunk_base_rhs) return false; // One null, one not

                // Since m_chunks store ColumnChunkBase<bool>, and PlainColumnChunk is ColumnChunkBase<bool>,
                // and we added operator== to ColumnChunkBase<bool> (PlainColumnChunk),
                // we can directly compare them if they are indeed instances of this specialization.
                // A dynamic_cast could be used for safety if m_chunks could hold other ColumnChunkBase<bool> subtypes.
                // However, PlainColumn::addChunk specifically takes shared_ptr<PlainColumnChunk>,
                // which is then stored as shared_ptr<ColumnChunkBase<bool>>.
                // So, they should be PlainColumnChunk instances.
                if (!(*chunk_base_lhs == *chunk_base_rhs)) { // This calls PlainColumnChunk::operator==
                    return false;
                }
            }
            return true;
        }
    };

} // namespace vaultdb

#endif // _COLUMN_BASE_H_