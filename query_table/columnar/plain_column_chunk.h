#ifndef PLAIN_COLUMN_CHUNK_H_
#define PLAIN_COLUMN_CHUNK_H_

#include <query_table/columnar/column_chunk_base.h>
#include <query_table/field/field.h>
#include <vector>
#include <memory>

namespace vaultdb {

    template<>
    class ColumnChunkBase<bool> {
    public:
        std::vector<PlainField> values;

        ColumnChunkBase() = default;

        explicit ColumnChunkBase(const std::vector<PlainField>& vals) : values(vals) {}

        virtual ~ColumnChunkBase() = default;

        virtual std::size_t size() const {
            return values.size();
        }

        const std::vector<PlainField>& getValues() const {
            return values;
        }

        void addValue(const PlainField& val) {
            values.push_back(val);
        }

        PlainField getValue(std::size_t index) const {
            return values.at(index);
        }

        // Equality operator
        bool operator==(const ColumnChunkBase<bool>& other) const {
            if (this == &other) return true;
            if (values.size() != other.values.size()) return false;
            // PlainField must have operator== defined
            for (size_t i = 0; i < values.size(); ++i) {
                if (values[i] != other.values[i]) {
                    return false;
                }
            }
            return true;
        }
    };

    typedef ColumnChunkBase<bool> PlainColumnChunk;

} // namespace vaultdb

#endif // PLAIN_COLUMN_CHUNK_H_
