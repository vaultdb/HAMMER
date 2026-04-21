#ifndef _COLUMN_TABLE_BASE_H_
#define _COLUMN_TABLE_BASE_H_

// Standard library includes needed by ColumnBase, PlainColumn, and ColumnTableBase
#include <string>
#include <vector>
#include <memory>
#include <cstddef>
#include <numeric>           // For std::accumulate (used in PlainColumn::getRowCount, potentially)
#include <stdexcept>         // For std::runtime_error, std::out_of_range, std::invalid_argument
#include <unordered_map>     // For ColumnTableBase::columns_
#include <type_traits>     // For std::is_same_v (used in ColumnTableBase constructor)

// Project-specific includes
#include "column_chunk_base.h"  // Defines ColumnChunkBase<B>
#include "plain_column_chunk.h" // Defines PlainColumnChunk
#include "column_base.h"

// These are needed for ColumnTableBase's constructor that takes a RowTable
#include <query_table/query_table.h>    // Defines QueryTable<B>
#include <query_table/query_schema.h>   // Defines QuerySchema
#include <query_table/field/field.h>    // Defines Field<B> and PlainField

namespace vaultdb {

    // Forward declaration for ColumnTableBase
    template<typename B> class ColumnTableBase;
    typedef ColumnTableBase<bool> PlainColumnTable;

    template<typename B>
    class ColumnTableBase {
    public:
        using RowTable = QueryTable<B>;

        // Only for PlainColumnTable (B=bool)
        std::shared_ptr<PlainColumn> getPlainColumn(const std::string& name) const {
            static_assert(std::is_same_v<B, bool>, "getPlainColumn is only valid for PlainColumnTable (B=bool)");
            auto base_col = this->getColumn(name);
            return std::dynamic_pointer_cast<PlainColumn>(base_col);
        }

        // Constructor for row-oriented to column-oriented conversion
        ColumnTableBase(RowTable* row_table) {
            if (!row_table) {
                throw std::invalid_argument("ColumnTableBase: Null RowTable provided to constructor.");
            }
            this->schema_ = row_table->getSchema();
            this->row_count_ = row_table->getTrueTupleCount();

            size_t column_count = this->schema_.getFieldCount();
            if (column_count == 0 && this->row_count_ > 0) {
                throw std::logic_error("ColumnTableBase: RowTable has rows but no columns in schema.");
            }
            if (column_count == 0 && this->row_count_ == 0) { // Empty table, no columns to create
                return;
            }

            std::vector<std::vector<Field<B>>> column_buffers(column_count);
            for(auto& buffer : column_buffers) {
                buffer.reserve(this->row_count_);
            }

            for (size_t r = 0; r < this->row_count_; ++r) {
                for (size_t col_idx = 0; col_idx < column_count; ++col_idx) {
                    column_buffers[col_idx].push_back(row_table->getField(r, col_idx));
                }
            }

            for (size_t col_idx = 0; col_idx < column_count; ++col_idx) {
                const QueryFieldDesc& field_desc = this->schema_.getField(col_idx);
                const std::string& col_name = field_desc.getName();
                std::vector<Field<B>>& col_vals = column_buffers[col_idx];

                if constexpr (std::is_same_v<B, bool>) {
                    // B is bool, so Field<B> is PlainField (Field<bool>).
                    // col_vals is std::vector<PlainField>&.
                    auto plain_chunk = std::make_shared<PlainColumnChunk>(col_vals); // Assumes PlainColumnChunk takes std::vector<PlainField>
                    auto plain_column = std::make_shared<PlainColumn>(col_name);
                    plain_column->addChunk(plain_chunk);
                    this->columns_[col_name] = plain_column; // Store concrete PlainColumn, upcast to ColumnBase<bool> is implicit
                } else {
                    // For other types of B (like void for FHE), this constructor would need a different strategy
                    // (e.g., a factory, or be specialized/overridden in derived table classes like FheColumnTable).
                    // FheColumnTable, for instance, handles its own conversion from PlainTable.
                    // So, this generic constructor is primarily useful for B=bool (PlainTable to PlainColumnTable).
                    throw std::logic_error("ColumnTableBase constructor from RowTable is primarily for B=bool (PlainTable to PlainColumnTable). Other types (e.g., FHE) should use specialized table constructors.");
                }
            }
        }

        // Constructor for external population (e.g., by PsqlDataProvider)
        ColumnTableBase(const QuerySchema& schema, size_t row_count)
                : schema_(schema), row_count_(row_count) {}

        virtual ~ColumnTableBase() = default;

        virtual std::size_t getRowCount() const { return row_count_; }
        virtual const QuerySchema& getSchema() const { return schema_; }

        virtual std::vector<std::string> getColumnNames() const {
            std::vector<std::string> names;
            names.reserve(columns_.size()); // Safe even if columns_ is empty
            for(const auto& pair : columns_) {
                names.push_back(pair.first);
            }
            return names;
        }

        virtual std::shared_ptr<ColumnBase<B>> getColumn(const std::string& name) const {
            auto it = columns_.find(name);
            if (it == columns_.end()) {
                return nullptr;
            }
            return it->second;
        }

        // Method for external population to add columns
        void addColumn(const std::string& name, std::shared_ptr<ColumnBase<B>> column) {
            if (!column) {
                throw std::invalid_argument("ColumnTableBase::addColumn: Cannot add a null column.");
            }
            if (name.empty()) {
                throw std::invalid_argument("ColumnTableBase::addColumn: Column name cannot be empty.");
            }
            if (columns_.count(name)) {
                throw std::runtime_error("ColumnTableBase::addColumn: Column with name '" + name + "' already exists.");
            }

            columns_[name] = column;
        }

        // Equality operator for ColumnTableBase
        bool operator==(const ColumnTableBase<B>& other) const {
            if (this == &other) return true;

            auto is_dummy = [](const QueryFieldDesc& f) {
                return f.getName() == "dummy_tag";
            };

            // 1. Compare Schemas
            // A simple check for now. QuerySchema should ideally have its own robust operator==.
            size_t this_real_fields  = 0;
            size_t other_real_fields = 0;

            for (int i = 0; i < this->schema_.getFieldCount(); ++i)
                if (!is_dummy(this->schema_.getField(i))) ++this_real_fields;
            for (int i = 0; i < other.schema_.getFieldCount(); ++i)
                if (!is_dummy(other.schema_.getField(i))) ++other_real_fields;

            if (this_real_fields != other_real_fields) return false;

            // 2. Compare Row Counts
            if (this->row_count_ != other.row_count_) return false;

            // 3. Compare Column Counts (from the internal map, should match schema field count if consistent)
//            if (this->columns_.size() != other.columns_.size()) return false;

            // 4. Compare individual columns. Iterate based on the order in this table's schema.
            for (int i = 0; i < this->schema_.getFieldCount(); ++i) { // Iterate by index
                const QueryFieldDesc& field_desc = this->schema_.getField(i); // Get current field_desc by index
                if (is_dummy(field_desc)) continue;

                const std::string& col_name = field_desc.getName();

                auto it_this = this->columns_.find(col_name);
                auto it_other = other.columns_.find(col_name);

                // Check if column exists in both tables under this name
                if (it_this == this->columns_.end() || it_other == other.columns_.end()) {
                    // This implies an inconsistency if schema listed it but it's not in the map,
                    // or that the column names in the schema didn't perfectly align with map keys across tables.
                    // If schema comparison was perfect and column counts matched, this means one table has the column in map, other doesn't.
                    return false;
                }

                const std::shared_ptr<ColumnBase<B>>& col_this_base_ptr = it_this->second;
                const std::shared_ptr<ColumnBase<B>>& col_other_base_ptr = it_other->second;

                if (!col_this_base_ptr && !col_other_base_ptr) continue; // Both columns are null, considered equal for this slot.
                if (!col_this_base_ptr || !col_other_base_ptr) return false; // One is null, the other isn't.

                // Actual comparison logic
                if constexpr (std::is_same_v<B, bool>) {
                    // This is a PlainColumnTable, so ColumnBase<bool> should be PlainColumn
                    const auto* plain_col_this = dynamic_cast<const PlainColumn*>(col_this_base_ptr.get());
                    const auto* plain_col_other = dynamic_cast<const PlainColumn*>(col_other_base_ptr.get());

                    if (!plain_col_this || !plain_col_other) {
                        // Should not happen if columns_ only stores PlainColumn for ColumnTableBase<bool>
                        return false; // Type mismatch or null after successful shared_ptr check
                    }
                    if (!(*plain_col_this == *plain_col_other)) {
                        return false;
                    }
                } else {
                    // For FheColumnTable (B=void) or other ColumnTableBase types,
                    // a specific comparison mechanism would be needed here.
                    // This could involve a virtual equals method in ColumnBase<B>
                    // or further template specializations/ SFINAE for ColumnTableBase::operator==.
                    // For the current goal of making PlainColumnTable comparable for tests, this branch means inequality.
                    // If you need to compare FheColumnTables, they would need their own FheColumn::operator== and so on.
                    return false;
                }
            }

            return true;
        }

        size_t getFieldCount() const {
            return field_count_;
        }

        void setFieldCount(size_t count) {
            field_count_ = count;
        }

        bool getHasDummy() const {
            return has_dummy_tag_;
        }

        void setHasDummy(bool dummy_flag) {
            has_dummy_tag_ = dummy_flag;
        }

    protected:
        ColumnTableBase() = default; // Protected default constructor

        std::unordered_map<std::string, std::shared_ptr<ColumnBase<B>>> columns_;
        QuerySchema schema_;
        size_t row_count_ = 0;
        size_t field_count_ = 0;
        bool has_dummy_tag_ = false;
    };

} // namespace vaultdb

#endif // _COLUMN_TABLE_BASE_H_