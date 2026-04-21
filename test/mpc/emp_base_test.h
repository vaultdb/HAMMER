#ifndef EMP_BASE_TEST_H
#define EMP_BASE_TEST_H
#include <gflags/gflags.h>
#include <gtest/gtest.h>
#include <query_table/query_table.h>
#include <util/logger.h>
#include <util/crypto_manager/emp_manager.h>
#include <util/google_test_flags.h>
// party, port, ctrl_port, alice_host, alice_db, bob_db, storage, unioned_db, cutoff, validation, filter from google_test_flags


using namespace vaultdb;

class EmpBaseTest  : public ::testing::Test {
protected:


    static const std::string empty_db_;
    CryptoMode emp_mode_;

    std::string db_name_; // set in setUp()
    StorageModel storage_model_ = StorageModel::COLUMN_STORE;
    EmpManager *manager_ = nullptr;
    int port_ = 54345;
    int ctrl_port_ = 65455;

    void SetUp() override;
    void TearDown() override;
    void disableBitPacking();
    void initializeBitPacking(const string & unioned_db);

};


#endif //EMP_BASE_TEST_H
