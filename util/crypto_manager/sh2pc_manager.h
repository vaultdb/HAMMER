#ifndef _SH2PC_MANAGER_
#define _SH2PC_MANAGER_

#include "emp_manager.h"
#include <util/system_configuration.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#if __has_include("emp-sh2pc/emp-sh2pc.h")
#include <emp-sh2pc/emp-sh2pc.h>

namespace  vaultdb {
    class SH2PCManager : public EmpManager {

    public:
        NetIO *netio_ = nullptr;
        int party_;

        SH2PCManager(const std::string& host, int party, int port, bool reverse_connect = false)  : party_(party) {
            const char* addr = nullptr;
            if (reverse_connect) {
                // Reverse TCP direction: ALICE connects, BOB listens
                // Protocol roles (garbler/evaluator) stay the same
                if (party_ == emp::ALICE) {
                    if (host.empty()) {
                        throw std::runtime_error("SH2PCManager: reverse_connect ALICE requires non-empty host");
                    }
                    addr = host.c_str();
                }
            } else {
                // Normal: ALICE listens, BOB connects
                if (party_ == emp::BOB) {
                    if (host.empty()) {
                        throw std::runtime_error("SH2PCManager: BOB requires non-empty ALICE host");
                    }
                    addr = host.c_str();
                }
            }

            netio_ = new emp::NetIO(addr, port);

            emp::setup_semi_honest(netio_, party_, 1024 * 16);
            SystemConfiguration & s = SystemConfiguration::getInstance();
            s.party_ = party;
            s.crypto_mode_ = CryptoMode::EMP_SH2PC;

            netio_->flush();
        }

        // set up EMP for insecure execution
        SH2PCManager()  {
            setup_plain_prot(false, "");
            SystemConfiguration & s = SystemConfiguration::getInstance();
            s.crypto_mode_ = CryptoMode::PLAIN;

        }

        int sendingParty() const override {
            return 0; // both are senders
        }

        size_t andGateCount() const override {
           return  emp::CircuitExecution::circ_exec->num_and();
        }

        size_t getCommCost() const override {
            return netio_->counter;
        }


        void  feed(Bit *labels, int party, const bool *b, int bit_cnt) override {
             emp::ProtocolExecution::prot_exec->feed((block *) labels, party, b, bit_cnt);
        }

        void flush() override { netio_->flush(); }

        ~SH2PCManager() {
            if(netio_ != nullptr) {
                emp::finalize_semi_honest();
                delete netio_;
            }
            else {
                finalize_plain_prot();
            }

        }

        QueryTable<Bit> *secretShare(const QueryTable<bool> *src) override;

        void reveal(bool *dst, const int & party, Bit *src, const int & bit_cnt) override {
            ProtocolExecution::prot_exec->reveal(dst, party, (block *) src, bit_cnt);
        }

        string revealToString(const emp::Integer & i, const int & party = PUBLIC)  const override {
           return  i.reveal<std::string>(party);
        }

        std::vector<emp::Integer> runInCircuitDecryption(
            const std::vector<int64_t>& partial_b,
            const std::vector<int64_t>& partial_c,
            const std::vector<int64_t>& mask_b,
            const std::vector<int64_t>& mask_c,
            uint64_t modulus);

        size_t getTableCardinality(const int & local_cardinality) override;

        inline void pack(Bit *src, Bit *dst, const int & bit_cnt)  override {
            memcpy(dst, src, bit_cnt * sizeof(Bit));
        }

        inline void unpack(Bit *src, Bit *dst, const int & bit_cnt)  override {
            memcpy(dst, src, bit_cnt * sizeof(Bit));
        }

        void sendPublic(const int & to_send) override {
            netio_->send_data(&to_send, 4);
            netio_->flush();
        }

        int recvPublic() override {
            int to_recv;
            netio_->recv_data(&to_recv, 4);
            netio_->flush();
            return to_recv;
        }

         void setDelta(const block & delta) override {
            throw;
        }


    private:
        static void secret_share_recv(const size_t &tuple_count, const int &dst_party,
                               QueryTable<Bit> *dst_table, const size_t &write_offset,
                               const bool &reverse_read_order);
        static void secret_share_send(const int &party, const QueryTable<bool> *src_table, QueryTable<Bit> *dst_table,
                                      const int &write_offset,
                                      const bool &reverse_read_order);
    };
}

#else

namespace  vaultdb {
    // placeholder to make it build when we're in other modes
    class SH2PCManager : public EmpManager {

    public:
        SH2PCManager(string alice_host, int party, int port, bool reverse_connect = false)  {
            throw;
        }

         SH2PCManager()  { throw; }

        int sendingParty() const override { throw; }

        size_t andGateCount() const override { return 0; }

        size_t getCommCost() const override { return 0; }

        void  feed(Bit *labels, int party, const bool *b, int byte_count) override  {
            throw;
        }

        void flush() override { throw; }

        ~SH2PCManager() = default;

        QueryTable<Bit> *secretShare(const QueryTable<bool> *src) override {
            throw;
        }

        void reveal(bool *dst, const int & party, Bit *src, const int & bit_cnt) override { throw; }

        string revealToString(const emp::Integer & i, const int & party = PUBLIC)  const override {
            throw;
        }

        std::vector<emp::Integer> runInCircuitDecryption(
            const std::vector<int64_t>&,
            const std::vector<int64_t>&,
            const std::vector<int64_t>&,
            const std::vector<int64_t>&,
            uint64_t) {
            throw;
        }

        size_t getTableCardinality(const int & local_cardinality) override {
            throw;
        }

        void pack(Bit *src, Bit *dst, const int & bit_cnt)  override {  throw; }

        void unpack(Bit *src, Bit *dst, const int & bit_cnt) override { throw; }

        void sendPublic(const int & to_send) override {
           throw;
        }

        int recvPublic() override {
            throw;
        }

        void setDelta(const block & delta) override {
            throw;
        }

    };
}
#endif // end if-emp-tool

#endif // end SH2PC_MANAGER_