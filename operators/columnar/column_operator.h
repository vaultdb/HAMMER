#ifndef _COLUMN_OPERATOR_H_
#define _COLUMN_OPERATOR_H_

#include <string>
#include <unordered_map>
#include <memory>
#include <vector>
#include <algorithm>
#include <chrono>
#include <query_table/columnar/column_table_base.h>
#include <util/system_configuration.h>
using std::chrono::high_resolution_clock;
using std::chrono::time_point;

namespace vaultdb {

    template<typename B> class ColumnOperator;

    template<typename B>
    class ColumnOperator {
    protected:
        // to enable CTEs we need to be able to have multiple parents
        vector<ColumnOperator *> parents_;
        ColumnOperator *lhs_child_ = nullptr;
        ColumnOperator *rhs_child_ = nullptr;
        std::shared_ptr<ColumnTableBase<B>> output_;
        SortDefinition sort_definition_; // start out with empty sort
        QuerySchema output_schema_;
        time_point<high_resolution_clock> start_time_, end_time_;
        size_t start_gate_cnt_ = 0L, gate_cnt_ = 0L;
        double runtime_ms_ = 0.0;
        bool operator_executed_ = false; // set when runSelf() executed once
        size_t output_cardinality_ = 0L;
        bool cte_flag_ = false;
        int operator_id_ = -1;

    public:
        ColumnOperator(const SortDefinition& sort_def, size_t output_cardinality)
                : sort_definition_(sort_def), output_cardinality_(output_cardinality) {}

        virtual ~ColumnOperator() = default;
        virtual std::shared_ptr<ColumnTableBase<B>> runSelf() = 0;
        /// Single execution entry point; delegates to runSelf().
        std::shared_ptr<ColumnTableBase<B>> run() { return runSelf(); }
        virtual OperatorType getType() const = 0;
        virtual std::string getParameters() const = 0;
        virtual void updateCollation() = 0;
        
        inline int getOperatorId() const { return operator_id_; }
        inline void setOperatorId(int op_id) { operator_id_ = op_id; }
        QuerySchema getOutputSchema() const { return output_schema_; }
        void setSchema(const QuerySchema& schema) { output_schema_ = schema; }
        size_t getOutputCardinality() const { return output_cardinality_; }
        SortDefinition getSortOrder() const { return sort_definition_; }
        
        // Timing helpers
        void startTiming() { start_time_ = high_resolution_clock::now(); }
        void endTiming() { 
            end_time_ = high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time_ - start_time_);
            runtime_ms_ = duration.count() / 1000.0;
        }
        double getRuntimeMs() const { return runtime_ms_; }
        void printTiming() const {
            std::string type_str = getTypeString();
            std::cout << "[Timing] Operator #" << operator_id_ << " (" << type_str << "): "
                      << runtime_ms_ << " ms";
            const OperatorType type = getType();
            const bool needs_rows = (type == OperatorType::FHE_SQL_INPUT ||
                                     type == OperatorType::FHE_FILTER ||
                                     type == OperatorType::FHE_AGGREGATE ||
                                     type == OperatorType::FHE_PROJECT);
            if (needs_rows && output_) {
                std::cout << ", rows=" << output_->getRowCount();
            }
            std::cout << std::endl;
        }
        
        // Get operator type name string (default implementation using getType())
        virtual std::string getTypeString() const {
            switch(getType()) {
                case OperatorType::FHE_SQL_INPUT:
                    return "FheTableScan";
                case OperatorType::FHE_FILTER:
                    return "FheFilter";
                case OperatorType::FHE_AGGREGATE:
                    return "FheAggregate";
                case OperatorType::FHE_PROJECT:
                    return "FheProject";
                case OperatorType::SECURE_CONTEXT_SWITCH:
                    return "SecureContextSwitch";
                default:
                    return "Unknown";
            }
        }
        
        // Accessors for child operators (similar to Operator<B>)
        ColumnOperator<B>* getChild(int idx = 0) const {
            if (idx == 0) return lhs_child_;
            return rhs_child_;
        }
        
        void setParent(ColumnOperator<B>* p) {
            // Note: parents_ uses ColumnOperator * (no template param, via forward declaration)
            // ColumnOperator<B>* is implicitly convertible to ColumnOperator*
            if (std::find(parents_.begin(), parents_.end(), static_cast<ColumnOperator*>(p)) == parents_.end())
                parents_.push_back(static_cast<ColumnOperator*>(p));
        }
        
        void setChild(ColumnOperator<B>* child, int idx = 0) {
            if (idx == 0) {
                lhs_child_ = child;
                if (child != nullptr) {
                    child->setParent(this);
                }
            } else {
                rhs_child_ = child;
                if (child != nullptr) {
                    child->setParent(this);
                }
            }
            if (child != nullptr) {
                this->updateCollation();
            }
        }
    };

} // namespace vaultdb

#endif // _COLUMN_OPERATOR_H_
