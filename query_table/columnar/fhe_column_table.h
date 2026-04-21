#ifndef FHE_COLUMN_TABLE_H_
#define FHE_COLUMN_TABLE_H_

#include <query_table/query_table.h>
#include "fhe_column.h"
#include "column_table_base.h"
#include <query_table/query_schema.h>
#include <query_table/field/field_type.h>
#include <query_table/field/field.h>

#include <unordered_map>
#include <unordered_set>
#include <map>
#include <string>
#include <stdexcept>
#include <vector>
#include <memory>
#include <cstddef>
#include <query_table/field/field.h>

namespace vaultdb {

    // Represents a range of slots within a ciphertext that belong to a specific group
    struct GroupRange {
        size_t group_id;        // Group identifier (index in bin_metadata)
        size_t start_slot;      // Starting slot index (inclusive)
        size_t end_slot;        // Ending slot index (inclusive)
        
        GroupRange(size_t gid, size_t start, size_t end)
            : group_id(gid), start_slot(start), end_slot(end) {}
        
        size_t size() const { return (end_slot >= start_slot) ? (end_slot - start_slot + 1) : 0; }
    };
    
    // Metadata for a single ciphertext chunk, storing which groups are present and their slot ranges
    struct ChunkMetadata {
        size_t chunk_index;                    // Chunk/Ciphertext index
        std::vector<GroupRange> group_ranges;  // List of groups in this chunk with their slot ranges
        
        ChunkMetadata(size_t idx) : chunk_index(idx) {}
        
        // Check if chunk contains multiple groups
        bool isMixed() const { return group_ranges.size() > 1; }
        
        // Get total packed count (sum of all range sizes)
        size_t getTotalPackedCount() const {
            size_t total = 0;
            for (const auto& range : group_ranges) {
                total += range.size();
            }
            return total;
        }
    };

    // Bin metadata structure for efficient group-by aggregation
    // Stores chunk index ranges and cardinality for each group without duplicating ciphertexts
    struct ColumnBinInfo {
        size_t start_chunk_idx;      // Starting chunk index for this bin
        size_t end_chunk_idx;        // Ending chunk index (inclusive) for this bin
        size_t total_packed_count;   // Total number of real data values (excluding padding)
        
        // Per-chunk slot range information for continuous packing
        // Maps chunk_index -> (start_slot, end_slot) within that chunk
        std::map<size_t, std::pair<size_t, size_t>> chunk_slot_ranges;
    };

    struct BinGroupMetadata {
        // Group key values (GROUP BY column values)
        std::vector<PlainField> group_key_values;
        
        // Bin information for each column (Key: column name)
        std::unordered_map<std::string, ColumnBinInfo> column_bin_info;
        
        // Original row range in the input data (for debugging/validation)
        size_t original_start_row;
        size_t original_end_row;
    };

    class FheColumnTable : public ColumnTableBase<void>, public std::enable_shared_from_this<FheColumnTable> {
    public:
        FheColumnTable(PlainTable* plain_table, const std::string& name = "");
        FheColumnTable(PlainColumnTable* plain_col_table,
                       const std::string& name = "",
                       const std::unordered_set<std::string>& encrypted_columns = {});
        FheColumnTable(std::shared_ptr<PlainColumnTable> plain_col_table,
                       const std::unordered_set<std::string>& encrypted_columns = {});
        FheColumnTable(const QuerySchema& schema, size_t row_count);

        std::shared_ptr<ColumnBase<void>> getColumn(const std::string& name) const override;
        std::vector<std::string> getColumnNames() const override;
        std::size_t getRowCount() const override;

        std::shared_ptr<FheColumn> getFheColumn(const std::string& name);
        std::shared_ptr<FheColumn> getFheColumn(const std::string& name) const;
        bool hasEncryptedColumn(const std::string& name) const;
        std::shared_ptr<FheColumn> ensureEncrypted(const std::string& name);
        std::shared_ptr<FheColumn> ensureEncrypted(const std::string& name) const;
        /// When for_aggregation is true, encrypt with getEffectiveRnsCount(max_val, row_count) RNS channels.
        std::shared_ptr<FheColumn> ensureEncrypted(const std::string& name, bool for_aggregation,
                                                  double max_val, uint64_t row_count);
        /// Ensure column is encrypted with exactly rns_level RNS channels (for indicator to match SUM column).
        std::shared_ptr<FheColumn> ensureEncrypted(const std::string& name, size_t rns_level);

        /// Encrypt one plain chunk on-the-fly without caching in columns_.
        /// Caller owns the returned FheColumnChunk and it is freed when it goes out of scope.
        /// Thread-safe: multiple threads may call with different chunk_idx simultaneously.
        std::shared_ptr<FheColumnChunk> encryptSingleChunk(
            const std::string& col_name,
            size_t             chunk_idx,
            size_t             rns_count = 1) const;

        void encryptColumns(const std::unordered_set<std::string>& columns = {});

        std::shared_ptr<PlainColumnTable> getPlainSnapshot() const { return plain_table_; }

        void addColumn(const std::shared_ptr<FheColumn>& column);
        void setDummyTagColumn(const std::shared_ptr<FheColumn>& dummy_tag_col);
        std::shared_ptr<FheColumn> getDummyTagColumn() const { return dummy_tag_column_; }

        const std::shared_ptr<PlainColumnTable>& getPlainTable() const { return plain_table_; }
        void setPlainTable(std::shared_ptr<PlainColumnTable> plain_table) { plain_table_ = plain_table; }

        PlainColumnTable* toPlainTable() const;
        PlainColumnTable* reveal() const;

        // Bin metadata accessors
        bool hasBinMetadata() const { return has_bin_metadata_; }
        const std::vector<BinGroupMetadata>& getBinMetadata() const { return bin_metadata_; }
        const std::vector<int32_t>& getBinGroupByOrdinals() const { return bin_group_by_ordinals_; }
        void setBinMetadata(const std::vector<BinGroupMetadata>& metadata, 
                          const std::vector<int32_t>& group_by_ordinals) {
            bin_metadata_ = metadata;
            bin_group_by_ordinals_ = group_by_ordinals;
            has_bin_metadata_ = true;
        }

    private:
        void initializeFromPlainColumns(std::shared_ptr<PlainColumnTable> plain_col_table,
                                        const std::unordered_set<std::string>& encrypted_columns);
        void addEncryptedColumn(const std::shared_ptr<FheColumn>& column);

        std::shared_ptr<FheColumn> processPlainColumnToFhe(
                const std::shared_ptr<PlainColumn>& plain_column,
                const QueryFieldDesc& field_desc);
        std::shared_ptr<FheColumn> processPlainColumnToBfv(
                const std::shared_ptr<PlainColumn>& plain_column,
                const QueryFieldDesc& field_desc);
        std::shared_ptr<FheColumn> processPlainColumnToBfvRns(
                const std::shared_ptr<PlainColumn>& plain_column,
                const QueryFieldDesc& field_desc,
                size_t rns_count);

        std::shared_ptr<PlainColumnTable> plain_table_;
        std::shared_ptr<FheColumn> dummy_tag_column_;
        
        // Bin metadata for efficient group-by aggregation
        bool has_bin_metadata_ = false;
        std::vector<BinGroupMetadata> bin_metadata_;
        std::vector<int32_t> bin_group_by_ordinals_;
    };

} // namespace vaultdb

#endif // FHE_COLUMN_TABLE_H_
