#include "fhe_column_chunk.h"
#include <query_table/field/fhe_type_abstraction.h>
#include "fhe_column_type.h"

namespace vaultdb {

// Factory method for creating CKKS column chunk
FheColumnChunk FheColumnChunk::createCKKS(const QuantizationParams& q_params, 
                                          const FheTypeDescriptor& type_desc,
                                          std::size_t packed_count) {
    auto fhe_value = FheTypeFactory::createCKKS(packed_count, q_params);
    return FheColumnChunk(std::move(fhe_value), packed_count, type_desc);
}

// Factory method for creating BFV column chunk
FheColumnChunk FheColumnChunk::createBFV(const QuantizationParams& q_params, 
                                         const FheTypeDescriptor& type_desc,
                                         std::size_t packed_count) {
    auto fhe_value = FheTypeFactory::createBFV(packed_count, q_params);
    return FheColumnChunk(std::move(fhe_value), packed_count, type_desc);
}

// Factory method for creating BGV column chunk
FheColumnChunk FheColumnChunk::createBGV(const QuantizationParams& q_params, 
                                         const FheTypeDescriptor& type_desc,
                                         std::size_t packed_count) {
    auto fhe_value = FheTypeFactory::createBGV(packed_count, q_params);
    return FheColumnChunk(std::move(fhe_value), packed_count, type_desc);
}

} // namespace vaultdb

