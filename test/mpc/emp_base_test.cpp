#include <util/data_utilities.h>
#include "emp_base_test.h"
#include <util/system_configuration.h>
#include "util/field_utilities.h"
#include "util/crypto_manager/sh2pc_manager.h"
#include "util/crypto_manager/sh2pc_outsourced_manager.h"
#include "util/crypto_manager/zk_manager.h"
#include "util/crypto_manager/outsourced_mpc_manager.h"
#include <util/logger.h>

#include "query_table/secure_tuple.h" // for use in child classes
#include "query_table/plain_tuple.h"

#include <boost/property_tree/json_parser.hpp>
#include <util/parsing_utilities.h>

#if  __has_include("emp-sh2pc/emp-sh2pc.h")
    static CryptoMode _emp_mode_ = CryptoMode::EMP_SH2PC;
#elif __has_include("emp-zk/emp-zk.h")
    static CryptoMode _emp_mode_ = CryptoMode::EMP_ZK;
#elif __has_include("emp-rescu/emp-rescu.h")
    static CryptoMode _emp_mode_ = CryptoMode::EMP_OUTSOURCED;
#else
    static CryptoMode _emp_mode_ = CryptoMode::EMP_PLAIN;
#endif

const std::string EmpBaseTest::empty_db_ = "tpch_empty";

using namespace Logging;

void EmpBaseTest::SetUp()  {
    SystemConfiguration & s = SystemConfiguration::getInstance();
    s.crypto_mode_ =  _emp_mode_;
    emp_mode_ =  _emp_mode_;
    // defaults to column store
    assert(FLAGS_storage == "column" || FLAGS_storage == "wire_packed" || FLAGS_storage == "compressed");
    if(FLAGS_storage == "wire_packed") {
        storage_model_ = StorageModel::PACKED_COLUMN_STORE;
    }
    else if(FLAGS_storage == "compressed") {
        storage_model_ = StorageModel::COMPRESSED_STORE;
    }

    s.setStorageModel(storage_model_);

    // default: everything is local
    std::string alice_host = FLAGS_alice_host; // Gflag overrides config file
    std::string bob_host = "127.0.0.1";
    std::string carol_host = "127.0.0.1";
    std::string trusted_party_host = "127.0.0.1";


    // TODO: remove hardcoded config file, replace with a gflag argument
    std::string config_json_path = Utilities::getCurrentWorkingDirectory() + "/conf/config.json";
    // parse IPs and ports from config.json
    ConnectionInfo c = ParsingUtilities::parseIPsFromJson(Utilities::getCurrentWorkingDirectory() + "/conf/config.json");
    // if port is customized in test, use the one from the CLI flags
    if (port_ != FLAGS_port) {
        port_ = FLAGS_port;
    }
    // otherwise try the one from the file
    else if (c.port_ != 0) {
        port_ = c.port_;
    }

    if (ctrl_port_ != FLAGS_ctrl_port) {
        ctrl_port_ = FLAGS_ctrl_port;
    }
    else if (c.ctrl_port_ != 0) {
        ctrl_port_ = c.ctrl_port_;
    }


	Logger* log = get_log();
    string settings = Utilities::getTestParameters();
    log->write(settings, Level::INFO);

    if (emp_mode_ == CryptoMode::EMP_SH2PC) {
        if (FLAGS_party == 1)
            log->write("Listening to port " + std::to_string(port_) + " as alice.", Level::INFO);
        else
            log->write("Connecting to " + alice_host + " on port " + std::to_string(port_) + " as bob.", Level::INFO);
    }

    if(emp_mode_ == CryptoMode::EMP_OUTSOURCED) { // host_list = {alice, bob, carol, trusted party}
        string hosts[] = {alice_host, bob_host, carol_host, trusted_party_host};

        // to enable wire packing set storage model to StorageModel::PACKED_COLUMN_STORE
        manager_ = new OutsourcedMpcManager(hosts, FLAGS_party, port_, ctrl_port_);
        db_name_ = (FLAGS_party == emp::TP) ? FLAGS_unioned_db : empty_db_;

        port_ += N;
        ctrl_port_ += N;
    }
    else if(emp_mode_ == CryptoMode::EMP_SH2PC) {
        assert(storage_model_ != StorageModel::PACKED_COLUMN_STORE);
        // if(storage_model_ == StorageModel::COMPRESSED_STORE) {
        //     manager_ = new SH2PCOutsourcedManager(alice_host, FLAGS_party, port);
        //     emp_mode_ = vaultdb::EmpMode::SH2PC_OUTSOURCED;
        //     db_name_ = (FLAGS_party == ALICE) ? FLAGS_unioned_db : empty_db_;
        // }
        // else {
            manager_ = new SH2PCManager(alice_host, FLAGS_party, port_);
            db_name_ = (FLAGS_party == emp::ALICE) ? FLAGS_alice_db : FLAGS_bob_db;
        // }
        // increment the port for each new test
        ++port_;
        ++ctrl_port_;
    }
    else if(emp_mode_ == CryptoMode::EMP_ZK_MODE) {
        assert(storage_model_ != StorageModel::PACKED_COLUMN_STORE);
        manager_ = new ZKManager(alice_host, FLAGS_party, port_);

        // Alice gets unioned DB to query entire dataset for ZK proof
        db_name_ = (FLAGS_party == ALICE) ? FLAGS_unioned_db : empty_db_;
        Utilities::mkdir("data");
        s.crypto_manager_ = manager_; // probably not needed
        // increment the port for each new test
        ++port_;
        ++ctrl_port_;
    }
    else {
        throw std::runtime_error("No EMP backend found.");
    }




    s.setEmptyDbName(empty_db_);
    s.crypto_manager_ = manager_;
    BitPackingMetadata md = FieldUtilities::getBitPackingMetadata(FLAGS_unioned_db);
    s.initialize(db_name_, md, storage_model_);
    s.setUnionedDbName(FLAGS_unioned_db);
}

void EmpBaseTest::TearDown() {
    manager_->flush();
    if(emp_mode_ == CryptoMode::EMP_ZK_MODE) {
        ZKManager *mgr = (ZKManager *) manager_;
        ASSERT_FALSE(mgr->finalize());
        delete mgr;
    }
    else {
        delete manager_;
    }
    SystemConfiguration::getInstance().crypto_manager_ = nullptr;
}



void EmpBaseTest::disableBitPacking() {
    SystemConfiguration & s = SystemConfiguration::getInstance();
    s.clearBitPacking();
}

// e.g.,unioned db = tpch_unioned_250
// local db = tpch_alice_250
void EmpBaseTest::initializeBitPacking(const string &unioned_db) {
    SystemConfiguration & s = SystemConfiguration::getInstance();
    BitPackingMetadata md = FieldUtilities::getBitPackingMetadata(unioned_db);
    s.initialize(unioned_db, md, storage_model_);
}


