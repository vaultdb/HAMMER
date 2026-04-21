#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <stdexcept>
#include <util/type_utilities.h>
#include <util/data_utilities.h>
#include <test/mpc/emp_base_test.h>
#include <test/support/tpch_queries.h>
#include <boost/algorithm/string/replace.hpp>
#include <parser/plan_parser.h>


using namespace emp;
using namespace vaultdb;


// MPC baseline comparison test for E6 experiment (Q1 + Q19)
// Same format as secure_tpch_test but reads plans from conf/plans/fhe/mpc-q*.json

class MpcComparisonTest : public EmpBaseTest {

protected:
    void runTest(const int &test_id, const SortDefinition &expected_sort);
    string generateExpectedOutputQuery(const int &test_id);

    int input_tuple_limit_ = 0;  // no truncation by default
};

void MpcComparisonTest::runTest(const int &test_id, const SortDefinition &expected_sort) {
    string plan_file = Utilities::getCurrentWorkingDirectory() + "/conf/plans/fhe/mpc-q" + std::to_string(test_id) + ".json";

    PlanParser<Bit> parser(db_name_, plan_file, input_tuple_limit_, true);
    SecureOperator *root = parser.getRoot();

    std::cout << "\n=== Plan Tree (Q" << test_id << ") ===" << std::endl;
    std::cout << root->printTree() << std::endl;
    std::cout << "=== End Plan Tree ===\n" << std::endl;

    auto result = root->run();

    if(FLAGS_validation) {
        string expected_sql = generateExpectedOutputQuery(test_id);
        PlainTable *expected = DataUtilities::getExpectedResults(FLAGS_unioned_db, expected_sql, false, 0);
        expected->order_by_ = expected_sort;
        PlainTable *observed = result->reveal();
        ASSERT_EQ(*expected, *observed);
        delete observed;
        delete expected;
    }
}

string MpcComparisonTest::generateExpectedOutputQuery(const int &test_id) {
    string query = tpch_queries[test_id];
    if (input_tuple_limit_ > 0) {
        query = (emp_mode_ == CryptoMode::EMP_SH2PC) ? truncated_tpch_queries[test_id] : truncated_tpch_queries_single_input_party[test_id];
        boost::replace_all(query, "$LIMIT", std::to_string(input_tuple_limit_));
    }
    return query;
}

TEST_F(MpcComparisonTest, tpch_q01) {
    SortDefinition expected_sort = DataUtilities::getDefaultSortDefinition(2);
    runTest(1, expected_sort);
}

TEST_F(MpcComparisonTest, tpch_q04) {
    SortDefinition expected_sort{ColumnSort(0, SortDirection::ASCENDING)};
    runTest(4, expected_sort);
}

TEST_F(MpcComparisonTest, tpch_q05) {
    SortDefinition expected_sort{ColumnSort(1, SortDirection::DESCENDING)};
    runTest(5, expected_sort);
}

TEST_F(MpcComparisonTest, tpch_q06) {
    SortDefinition expected_sort{ColumnSort(0, SortDirection::ASCENDING)};
    runTest(6, expected_sort);
}

TEST_F(MpcComparisonTest, tpch_q12) {
    SortDefinition expected_sort{ColumnSort(0, SortDirection::ASCENDING)};
    runTest(12, expected_sort);
}

TEST_F(MpcComparisonTest, tpch_q19) {
    SortDefinition expected_sort{ColumnSort(0, SortDirection::ASCENDING)};
    runTest(19, expected_sort);
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    gflags::ParseCommandLineFlags(&argc, &argv, false);

	::testing::GTEST_FLAG(filter)=FLAGS_filter;
    int i = RUN_ALL_TESTS();
    google::ShutDownCommandLineFlags();
    return i;
}
