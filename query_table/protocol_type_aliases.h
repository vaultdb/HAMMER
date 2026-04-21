#ifndef PROTOCOL_TYPE_ALIASES_H_
#define PROTOCOL_TYPE_ALIASES_H_

#include "query_table/field/field.h"
#include "query_table/field/fhe_field.h"
#include "query_table/field/fhe_type_abstraction.h"
#include "query_table/columnar/column_chunk_base.h"
#include "query_table/columnar/plain_column_chunk.h"
#include "query_table/columnar/fhe_column_chunk.h"

namespace vaultdb {

// ============================================================================
// PROTOCOL TYPE ALIASES
// ============================================================================

// Plaintext Protocol Types
typedef Field<bool> PlainField;
typedef ColumnChunkBase<bool> PlainColumnChunk;

// EMP Protocol Types (if using EMP library)
// typedef Field<Bit> SecureField;
// typedef ColumnChunkBase<Bit> SecureColumnChunk;

// FHE Protocol Types - Polymorphic (can hold any FHE scheme)
typedef Field<FheTypeBase*> FheField;
typedef ColumnChunkBase<FheTypeBase*> FheColumnChunk;

// FHE Protocol Types - Type-Specific (one per data type)
typedef Field<FheIntegerType> FheIntegerField;   // For integers (BFV/BGV)
typedef Field<FheRealType> FheRealField;         // For reals (CKKS)
typedef Field<FheBooleanType> FheBooleanField;   // For booleans (FHEW/TFHE)

typedef ColumnChunkBase<FheIntegerType> FheIntegerColumnChunk;
typedef ColumnChunkBase<FheRealType> FheRealColumnChunk;
typedef ColumnChunkBase<FheBooleanType> FheBooleanColumnChunk;

// ============================================================================
// PROTOCOL SWITCHING MACROS
// ============================================================================

// Easy protocol switching - change these defines to switch protocols
#define VAULTDB_PROTOCOL_PLAINTEXT
// #define VAULTDB_PROTOCOL_EMP
// #define VAULTDB_PROTOCOL_FHE_INTEGER  // BFV/BGV for integers
// #define VAULTDB_PROTOCOL_FHE_REAL     // CKKS for reals
// #define VAULTDB_PROTOCOL_FHE_BOOLEAN  // FHEW/TFHE for booleans
// #define VAULTDB_PROTOCOL_FHE_MIXED    // Allow multiple schemes in one system

#ifdef VAULTDB_PROTOCOL_PLAINTEXT
    typedef PlainField ProtocolField;
    typedef PlainColumnChunk ProtocolColumnChunk;
    typedef bool ProtocolBooleanType;
    
#elif defined(VAULTDB_PROTOCOL_EMP)
    typedef SecureField ProtocolField;
    typedef SecureColumnChunk ProtocolColumnChunk;
    typedef Bit ProtocolBooleanType;
    
#elif defined(VAULTDB_PROTOCOL_FHE_INTEGER)
    typedef FheIntegerField ProtocolField;
    typedef FheIntegerColumnChunk ProtocolColumnChunk;
    typedef FheIntegerType ProtocolType;
    
#elif defined(VAULTDB_PROTOCOL_FHE_REAL)
    typedef FheRealField ProtocolField;
    typedef FheRealColumnChunk ProtocolColumnChunk;
    typedef FheRealType ProtocolType;
    
#elif defined(VAULTDB_PROTOCOL_FHE_BOOLEAN)
    typedef FheBooleanField ProtocolField;
    typedef FheBooleanColumnChunk ProtocolColumnChunk;
    typedef FheBooleanType ProtocolType;
    
#elif defined(VAULTDB_PROTOCOL_FHE_MIXED)
    // In mixed mode, we use polymorphic FHE types
    typedef FheField ProtocolField;
    typedef FheColumnChunk ProtocolColumnChunk;
    typedef FheTypeBase* ProtocolType;
    
#else
    #error "No protocol defined! Please define one of VAULTDB_PROTOCOL_* macros"
#endif

// ============================================================================
// PROTOCOL-AGNOSTIC TEMPLATE ALIASES
// ============================================================================

// Template aliases for protocol-agnostic code
template<typename B>
using ProtocolFieldType = Field<B>;

template<typename B>
using ProtocolColumnChunkType = ColumnChunkBase<B>;

// ============================================================================
// PROTOCOL DETECTION UTILITIES
// ============================================================================

namespace ProtocolUtils {
    
    enum class ProtocolType {
        PLAINTEXT,
        EMP,
        FHE_INTEGER,    // BFV/BGV
        FHE_REAL,       // CKKS
        FHE_BOOLEAN,    // FHEW/TFHE
        FHE_MIXED       // Multiple schemes
    };
    
    constexpr ProtocolType getCurrentProtocol() {
#ifdef VAULTDB_PROTOCOL_PLAINTEXT
        return ProtocolType::PLAINTEXT;
#elif defined(VAULTDB_PROTOCOL_EMP)
        return ProtocolType::EMP;
#elif defined(VAULTDB_PROTOCOL_FHE_INTEGER)
        return ProtocolType::FHE_INTEGER;
#elif defined(VAULTDB_PROTOCOL_FHE_REAL)
        return ProtocolType::FHE_REAL;
#elif defined(VAULTDB_PROTOCOL_FHE_BOOLEAN)
        return ProtocolType::FHE_BOOLEAN;
#elif defined(VAULTDB_PROTOCOL_FHE_MIXED)
        return ProtocolType::FHE_MIXED;
#else
        static_assert(false, "No protocol defined!");
#endif
    }
    
    constexpr bool isPlaintext() {
        return getCurrentProtocol() == ProtocolType::PLAINTEXT;
    }
    
    constexpr bool isEMP() {
        return getCurrentProtocol() == ProtocolType::EMP;
    }
    
    constexpr bool isFHE() {
        auto protocol = getCurrentProtocol();
        return protocol == ProtocolType::FHE_INTEGER || 
               protocol == ProtocolType::FHE_REAL || 
               protocol == ProtocolType::FHE_BOOLEAN ||
               protocol == ProtocolType::FHE_MIXED;
    }
    
    constexpr bool isFHEInteger() {
        return getCurrentProtocol() == ProtocolType::FHE_INTEGER;
    }
    
    constexpr bool isFHEReal() {
        return getCurrentProtocol() == ProtocolType::FHE_REAL;
    }
    
    constexpr bool isFHEBoolean() {
        return getCurrentProtocol() == ProtocolType::FHE_BOOLEAN;
    }
    
    constexpr bool isFHEMixed() {
        return getCurrentProtocol() == ProtocolType::FHE_MIXED;
    }
}

// ============================================================================
// EXAMPLE USAGE
// ============================================================================

/*
// ============================================================================
// USAGE EXAMPLES
// ============================================================================

// Example 1: Protocol-agnostic operator (works with any protocol)
// ---------------------------------------------------------------
template<typename B>
class ProtocolAgnosticJoin : public ColumnOperator<B> {
    std::shared_ptr<ColumnTable<B>> lhs_table_;
    std::shared_ptr<ColumnTable<B>> rhs_table_;
    
    std::shared_ptr<ColumnTable<B>> performJoin() {
        // Same code works for plaintext, EMP, and all FHE schemes!
        auto lhs_key = lhs_table_->getColumn(join_key_);
        auto rhs_key = rhs_table_->getColumn(join_key_);
        auto match_mask = lhs_key == rhs_key;  // Overloaded for each protocol
        return applyMask(match_mask);
    }
};

// Example 2: Easy protocol switching
// ----------------------------------
// To switch from Real (CKKS) to Integer (BFV), just change one line:
// #undef VAULTDB_PROTOCOL_FHE_REAL
// #define VAULTDB_PROTOCOL_FHE_INTEGER

// Example 3: Mixed FHE system (multiple schemes in one system)
// ------------------------------------------------------------
#ifdef VAULTDB_PROTOCOL_FHE_MIXED
void processData() {
    // Use different schemes for different columns!
    auto integer_col = FheTypeFactory::createInteger(1024);  // BFV for integers
    auto real_col = FheTypeFactory::createReal(1024);        // CKKS for reals
    auto bool_col = FheTypeFactory::createBoolean(1024);     // TFHE for booleans
    
    // All columns can coexist in the same table
    table->addColumn("age", integer_col);
    table->addColumn("salary", real_col);
    table->addColumn("active", bool_col);
}
#endif

// Example 4: Protocol-specific optimizations
// ------------------------------------------
template<typename B>
void optimizeForProtocol() {
    if constexpr (std::is_same_v<B, bool>) {
        // Plaintext optimizations
        std::cout << "Using plaintext protocol" << std::endl;
        
    } else if constexpr (std::is_same_v<B, FheTypeBase*>) {
        // FHE optimizations
        if (ProtocolUtils::isFHEReal()) {
            // CKKS-specific: approximate arithmetic
            std::cout << "Using CKKS for real arithmetic" << std::endl;
            
        } else if (ProtocolUtils::isFHEInteger()) {
            // BFV/BGV-specific: exact integer arithmetic
            std::cout << "Using BFV for integer arithmetic" << std::endl;
            
        } else if (ProtocolUtils::isFHEBoolean()) {
            // TFHE-specific: boolean circuits
            std::cout << "Using TFHE for boolean circuits" << std::endl;
            
        } else if (ProtocolUtils::isFHEMixed()) {
            // Mixed mode: handle polymorphically
            std::cout << "Using mixed FHE schemes" << std::endl;
        }
    }
}

// Example 5: Type-based dispatch for FHE operations
// -------------------------------------------------
void processFheValue(FheTypeBase* value) {
    switch (value->getSchemeType()) {
        case FheSchemeType::INTEGER:
            // Process as integer (BFV/BGV)
            std::cout << "Processing integer value" << std::endl;
            break;
            
        case FheSchemeType::REAL:
            // Process as real (CKKS)
            std::cout << "Processing real value" << std::endl;
            break;
            
        case FheSchemeType::BOOLEAN:
            // Process as boolean (TFHE)
            std::cout << "Processing boolean value" << std::endl;
            break;
    }
}

// Example 6: Scheme switching for complex operations
// --------------------------------------------------
// As per OpenFHE documentation, you can switch between schemes:
// - CKKS ↔ FHEW/TFHE for non-smooth functions (comparison, etc.)
// - RLWE ↔ CKKS for lookup tables
void performComplexOperation() {
    auto ckks_value = FheTypeFactory::createReal(1024);
    
    // Perform arithmetic in CKKS
    // ... (additions, multiplications)
    
    // Switch to TFHE for comparison
    auto tfhe_value = FheTypeFactory::createBoolean(1024);
    // ... (perform comparison)
    
    // Switch back to CKKS for more arithmetic
    auto result = FheTypeFactory::createReal(1024);
}
*/

} // namespace vaultdb

#endif // PROTOCOL_TYPE_ALIASES_H_
