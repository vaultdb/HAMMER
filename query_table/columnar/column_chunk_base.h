#ifndef _COLUMN_CHUNK_BASE_H_
#define _COLUMN_CHUNK_BASE_H_
#include <cstddef>
#include <memory>

namespace vaultdb {

    // Forward declaration for FHE types
    class FheTypeBase;

    template<typename B>
    class ColumnChunkBase {
    public:
        virtual ~ColumnChunkBase() = default;
        // Add virtual methods that every column chunk type must implement
        virtual size_t size() const = 0; // number of items/slots in the chunk
        // Potentially add a method related to B, e.g., to get a dummy value of type B
        // virtual B getDummyValue() const = 0;
        // Or methods to access raw data if B represents the underlying data type in some cases
    };

    // Specialization for FHE types
    template<>
    class ColumnChunkBase<FheTypeBase*> {
    public:
        virtual ~ColumnChunkBase() = default;
        virtual size_t size() const = 0;
        virtual std::unique_ptr<FheTypeBase> getPackedValue() const = 0;
        virtual void setPackedValue(std::unique_ptr<FheTypeBase> value) = 0;
    };

} // namespace vaultdb

#endif // _COLUMN_CHUNK_BASE_H_
