#ifndef _SECURE_CONTEXT_SWITCH_H_
#define _SECURE_CONTEXT_SWITCH_H_

#include <operators/operator.h>
#include <operators/columnar/column_operator.h>
#include <query_table/columnar/fhe_column_table.h>
#include <query_table/query_table.h>
#include <query_table/query_schema.h>
#include <util/fhe/fhe_network.h>
#include <util/crypto_manager/sh2pc_manager.h>
#include <common/defs.h>
#include <string>
#include <memory>

namespace vaultdb {

// SecureContextSwitch (Adapter): FHE -> MPC transition.
// Inherits Operator<emp::Bit> so Sort<emp::Bit> can use it as child without type erasure.
class SecureContextSwitch : public Operator<emp::Bit> {
    // FHE subtree root (plan-driven Party B). Cast to ColumnOperator<void> to call runSelf().
    Operator<void>* fhe_child_ = nullptr;
    std::shared_ptr<FheColumnTable> input_table_;
    SecureTable* secure_table_ = nullptr;

    int mpc_port_;
    std::string charlie_host_;
    bool decryption_in_mpc_;
    int mpc_in_circuit_port_;

    std::unique_ptr<FheNetworkIO> mpc_network_io_;
    SH2PCManager* mpc_mgr_temp_ = nullptr;

    SortDefinition sort_def_;
    int limit_ = -1;

    /// Set by Party B when running; used so Party A can display decimal columns as value/10^6.
    QuerySchema display_schema_for_party_a_;
    bool display_schema_set_ = false;

    static QuerySchema BuildSafeSchema(const QuerySchema& schema);

public:
    // Plan-driven: FHE child op. Parser passes Operator<void>* (ColumnOperator<void> stored as void*).
    SecureContextSwitch(Operator<void>* fhe_child,
                        int mpc_port = 8777,
                        const std::string& charlie_host = "127.0.0.1",
                        bool decryption_in_mpc = false,
                        int mpc_in_circuit_port = 12345);

    // Direct FheColumnTable (e.g. testing).
    SecureContextSwitch(std::shared_ptr<FheColumnTable> input_table,
                        int mpc_port = 8777,
                        const std::string& charlie_host = "127.0.0.1",
                        bool decryption_in_mpc = false,
                        int mpc_in_circuit_port = 12345);

    // Party C listener: no input; receives schema and M-R from Party B.
    SecureContextSwitch(int mpc_port,
                        const std::string& charlie_host = "127.0.0.1",
                        bool decryption_in_mpc = false,
                        int mpc_in_circuit_port = 12345);

    ~SecureContextSwitch() override;

    QueryTable<emp::Bit>* runSelf() override;
    Operator<emp::Bit>* clone() const override;
    bool operator==(const Operator<emp::Bit>& other) const override;
    void updateCollation() override {}

    OperatorType getType() const override { return OperatorType::SECURE_CONTEXT_SWITCH; }
    std::string getParameters() const override;

    SecureTable* getSecureTable() const { return secure_table_; }
    FheNetworkIO* getMpcNetworkIO() { return mpc_network_io_.get(); }

    void setSortDefinition(const SortDefinition& sd);
    void setLimit(int l) { limit_ = l; }
    const SortDefinition& getSortDefinition() const { return sort_def_; }
    int getLimit() const { return limit_; }

    /// If Party B has run, returns the schema to use for display (FLOAT preserved for decimal cols). Otherwise nullptr.
    const QuerySchema* getDisplaySchemaForPartyA() const {
        return display_schema_set_ ? &display_schema_for_party_a_ : nullptr;
    }
};

}  // namespace vaultdb

#endif  // _SECURE_CONTEXT_SWITCH_H_
