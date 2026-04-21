#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <util/type_utilities.h>
#include <stdexcept>
#include <test/fhe/fhe_base_test.h>
#include <parser/plan_parser.h>
#include <operators/columnar/column_operator.h>
#include <util/utilities.h>
#include <iostream>

using namespace lbcrypto;
using namespace vaultdb;

// Flags in util/google_test_flags.cpp, DECLAREd in util/google_test_flags.h
class FhePlanParserTest : public FheBaseTest {
protected:
    void printOperatorTree(ColumnOperator<void>* op, int indent = 0);
    void runTest(const std::string& test_name);
    int input_tuple_limit_ = -1;
};

void FhePlanParserTest::printOperatorTree(ColumnOperator<void>* op, int indent) {
    if (!op) return;
    
    std::string indent_str(indent * 4, ' ');
    
    // Print operator info
    std::cout << indent_str << "#" << op->getOperatorId() << ": ";
    
    // Print operator type
    std::string type_str;
    switch (op->getType()) {
        case OperatorType::FHE_SQL_INPUT:
            type_str = "FheTableScan";
            break;
        case OperatorType::FHE_FILTER:
            type_str = "FheFilter";
            break;
        case OperatorType::FHE_AGGREGATE:
            type_str = "FheAggregate";
            break;
        default:
            type_str = "Unknown";
            break;
    }
    
    std::cout << type_str << "<void>";
    
    // Print parameters
    std::string params = op->getParameters();
    if (!params.empty()) {
        std::cout << " (" << params << ")";
    }
    
    std::cout << std::endl;
    
    // Print children recursively
    if (op->getChild(0)) {
        printOperatorTree(op->getChild(0), indent + 1);
    }
}

void FhePlanParserTest::runTest(const std::string& test_name) {
    std::string plan_file = Utilities::getCurrentWorkingDirectory() + "/conf/plans/fhe/" + test_name + ".json";
    
    std::cout << "[FhePlanParserTest] Parsing plan: " << test_name << std::endl;
    std::cout << "[FhePlanParserTest] Plan file: " << plan_file << std::endl;
    
    // Parse JSON plan
    PlanParser<void> parser(db_name_, plan_file, input_tuple_limit_, true);
    Operator<void>* root = parser.getRoot();
    
    if (!root) {
        throw std::runtime_error("FhePlanParserTest: plan parser returned null root operator");
    }
    
    // Cast to ColumnOperator<void> (stored as Operator<void>* via reinterpret_cast)
    // Note: reinterpret_cast doesn't fail, it just reinterprets the pointer type
    auto column_op = reinterpret_cast<ColumnOperator<void>*>(root);
    
    // Print operator tree
    std::cout << "\n=== FHE Operator Tree ===" << std::endl;
    printOperatorTree(column_op);
    std::cout << "==========================\n" << std::endl;
}

TEST_F(FhePlanParserTest, q1) {
    runTest("q1");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    
    ::testing::GTEST_FLAG(filter) = FLAGS_filter;
    int i = RUN_ALL_TESTS();
    google::ShutDownCommandLineFlags();
    return i;
}







