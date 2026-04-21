#ifndef _SYSTEM_CONFIGURATION_H
#define _SYSTEM_CONFIGURATION_H
#include <string>
#include <map>
#include <memory>
#include "common/defs.h"
#include <iostream>
#include "util/buffer_pool/buffer_pool_manager.h"
#include <query_table/query_schema.h>

// Forward declarations to avoid circular dependencies
namespace vaultdb {
    class EmpManager;
    class FheManager;
    class CryptoManager;  // Legacy
}

using namespace std;

// warning: do not include emp-based classes like netio here - it conflicts with the static, singleton setup
// creates mysterious compile-time bugs

namespace vaultdb{

    class FheNetworkIO;

    typedef struct table_metadata_ {
        string name_;
        QuerySchema schema_;
        SortDefinition collation_;
        size_t tuple_cnt_;

        bool operator==(const table_metadata_ &other) const {
            // need to do vectorEquality here without Utilities because of circular dependency
            if(collation_.size() != other.collation_.size()) return false;
            for(int i = 0; i < collation_.size(); ++i) if(collation_[i] != other.collation_[i]) return false;
            return name_ == other.name_ && schema_ == other.schema_  && tuple_cnt_ == other.tuple_cnt_;
        }

        string toString() const {
            std::stringstream s;
            s << name_ << ": " << schema_.prettyPrint() << ", cardinality: " << tuple_cnt_ << ", collation: ";
            // copy and paste of DataUtilities::printSortDefinition to avoid dependency
            s << "{";
            bool init = false;
            for(ColumnSort c : collation_) {
                if(init)
                    s << ", ";
                string direction = (c.second == SortDirection::ASCENDING) ? "ASC" : (c.second == SortDirection::DESCENDING) ? "DESC" : "INVALID";
                s << "<" << c.first << ", "
                       << direction << "> ";

                init = true;
            }

            s << "}";
            return s.str();

        }

    } TableMetadata;


    class SystemConfiguration {

    public:

        // === Dual-backend architecture ===
        EmpManager* mpc_ = nullptr;     // MPC backend (EMP-based: SH2PC, ZK, OMPC)
        FheManager* fhe_ = nullptr;     // FHE backend (OpenFHE-based)
        
        // === Legacy (for backward compatibility) ===
        CryptoManager *crypto_manager_ = nullptr;  // Points to mpc_ for legacy code
        
        CryptoMode crypto_mode_ = CryptoMode::PLAIN;
        int party_;
        int input_party_ = 10086;
        // Optional network handle for 2-party FHE protocols (set by tests)
        FheNetworkIO* fhe_network_io_ = nullptr;

        bool buffer_pool_enabled_ = false; // for OMPC only for now
        BufferPoolManager & bpm_ = BufferPoolManager::getInstance();
        int num_tables_ = 0;
        int bp_page_size_bits_ = 2048;
        int bp_page_cnt_ = 50;
        string temp_db_path_; // for use with pages or wires evicted from BP
        string stored_db_path_;
        map<string, TableMetadata> table_metadata_;


        static SystemConfiguration& getInstance() {
            static SystemConfiguration  instance;
            return instance;
        }

        // for sh2pc and ZK mostly
        void initialize(const string &db_name, const std::map<ColumnReference, BitPackingDefinition> &bp, const StorageModel &model) {
            unioned_db_name_ = db_name;
            bit_packing_ = bp;
            cout << "Initializing bit packing with " << bp.size() << " columns" << endl;
            storage_model_ = model;

            if(buffer_pool_enabled_) {
                bpm_.initialize(bp_page_size_bits_, bp_page_cnt_, crypto_manager_);
            }
        }

        void initialize(const string &db_name, const std::map<ColumnReference, BitPackingDefinition> &bp,
                        const StorageModel &model, const int & bp_page_size_bits, const int & bp_page_cnt) {
            unioned_db_name_ = db_name;
            bit_packing_ = bp;
            storage_model_ = model;
            bp_page_size_bits_ = bp_page_size_bits;
            bp_page_cnt_ = bp_page_cnt;

            if(buffer_pool_enabled_) {
                bpm_.initialize(bp_page_size_bits_, bp_page_cnt_, crypto_manager_);
            }
        }

        void initializeWirePackedDb(const string & db_path, const std::string & temp_data_path);
        void initializeOutsourcedSecretShareDb(const string & db_path, const std::string & temp_data_path);

        string getUnionedDbName() const { return unioned_db_name_; }
        void setUnionedDbName(const string & db_name) { unioned_db_name_ = db_name; }
        string getEmptyDbName() const { return empty_db_name_; }
        void setEmptyDbName(const string & db_name) { empty_db_name_ = db_name; }
        inline bool inputParty() { return party_ == input_party_; }

        BitPackingDefinition getBitPackingSpec(const string & table_name, const string & col_name);
        SystemConfiguration(const SystemConfiguration&) = delete;
        SystemConfiguration& operator=(const SystemConfiguration &) = delete;

        inline void clearBitPacking() {
            bit_packing_.clear();
        }


        inline StorageModel storageModel() const {
            return storage_model_;
        }

        inline void setStorageModel(const StorageModel & model) {
            storage_model_ = model;
        }

        inline size_t andGateCount() const {
            return (crypto_manager_ != nullptr)  ? crypto_manager_->andGateCount() : 0L;
        }

        inline void flush() const {
            if(crypto_manager_ != nullptr) crypto_manager_->flush();
        }

        inline void setFheNetworkIO(FheNetworkIO* net) { fhe_network_io_ = net; }
        inline FheNetworkIO* getFheNetworkIO() const { return fhe_network_io_; }
        
        // === Dual-backend accessors ===
        inline EmpManager* mpc() { return mpc_; }
        inline FheManager* fhe() { return fhe_; }
        inline bool hasMpc() const { return mpc_ != nullptr; }
        inline bool hasFhe() const { return fhe_ != nullptr; }
        
        // Set MPC backend
        inline void setMpc(EmpManager* m) { 
            mpc_ = m; 
            // Update legacy alias
            crypto_manager_ = m;
        }
        
        // Set FHE backend
        inline void setFhe(FheManager* f) { 
            fhe_ = f; 
        }

        ~SystemConfiguration() {
            // crypto_manager_ is non-owning alias, don't delete
            // mpc_ and fhe_ are managed externally (by tests/applications)
            // TODO: Consider using unique_ptr for ownership clarity
        }

        bool bitPackingEnabled() const {
            return !bit_packing_.empty();
        }


    private:
        SystemConfiguration() { }

        string unioned_db_name_, empty_db_name_; // empty DB used for schema lookups (for public info)
        StorageModel storage_model_ = StorageModel::COLUMN_STORE; // only support one storage model at a time
        std::map<ColumnReference, BitPackingDefinition> bit_packing_;
    };

}
#endif //_SYSTEM_CONFIGURATION_H
