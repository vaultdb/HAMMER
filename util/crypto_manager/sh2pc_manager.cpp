#include "sh2pc_manager.h"

#if __has_include("emp-sh2pc/emp-sh2pc.h")
#include <emp-sh2pc/emp-sh2pc.h>
#include <query_table/query_table.h>
#include <util/field_utilities.h>
#include <operators/sort.h>

using namespace vaultdb;

size_t SH2PCManager::getTableCardinality(const int &local_cardinality) {
    int alice_tuple_cnt = local_cardinality;
    int bob_tuple_cnt = local_cardinality;
    if (party_ == ALICE) {
        netio_->send_data(&alice_tuple_cnt, 4);
        netio_->flush();
        netio_->recv_data(&bob_tuple_cnt, 4);
        netio_->flush();
    } else if (party_ == BOB) {
        netio_->recv_data(&alice_tuple_cnt, 4);
        netio_->flush();
        netio_->send_data(&bob_tuple_cnt, 4);
        netio_->flush();
    }

    return alice_tuple_cnt + bob_tuple_cnt;

}


QueryTable<Bit> *SH2PCManager::secretShare(const QueryTable<bool> *src) {
    size_t alice_tuple_cnt =  src->tuple_cnt_;
    size_t bob_tuple_cnt = alice_tuple_cnt;

    if (party_ == ALICE) {
        netio_->send_data(&alice_tuple_cnt, 4);
        netio_->flush();
        netio_->recv_data(&bob_tuple_cnt, 4);
        netio_->flush();
    } else if (party_ == BOB) {
        netio_->recv_data(&alice_tuple_cnt, 4);
        netio_->flush();
        netio_->send_data(&bob_tuple_cnt, 4);
        netio_->flush();
    }


    QuerySchema dst_schema = QuerySchema::toSecure(src->getSchema());

    auto dst_table = QueryTable<Bit>::getTable(alice_tuple_cnt + bob_tuple_cnt, dst_schema, src->order_by_);

    if(!src->order_by_.empty()) {
        if (party_ == emp::ALICE) {
            if(alice_tuple_cnt > 0) secret_share_send(emp::ALICE, src, dst_table, 0, (bob_tuple_cnt > 0));
            if(bob_tuple_cnt > 0) secret_share_recv(bob_tuple_cnt, emp::BOB, dst_table, alice_tuple_cnt, false);

        } else { // bob
            if(alice_tuple_cnt > 0) secret_share_recv(alice_tuple_cnt, emp::ALICE, dst_table, 0, (bob_tuple_cnt > 0));
            if(bob_tuple_cnt > 0)  secret_share_send(emp::BOB, src, dst_table, alice_tuple_cnt, false);
        }

        int counter;
        // if one is empty, then we are already sorted
        if(alice_tuple_cnt > 0 && bob_tuple_cnt > 0) {
            auto dst_sort = dst_table->order_by_;
            Sort<Bit>::bitonicMerge(dst_table, dst_sort, 0, dst_table->tuple_cnt_, true, counter);
            dst_table->order_by_ = dst_sort;

        }
    }
    else { // concatenate Alice and Bob
        if (party_ == emp::ALICE) {
            if(alice_tuple_cnt > 0) secret_share_send(emp::ALICE, src, dst_table, 0, false);
            if(bob_tuple_cnt > 0)  secret_share_recv(bob_tuple_cnt, emp::BOB, dst_table, alice_tuple_cnt, false);
        } else { // bob
            if(alice_tuple_cnt > 0) secret_share_recv(alice_tuple_cnt, emp::ALICE, dst_table, 0, false);
            if(bob_tuple_cnt > 0)  secret_share_send(emp::BOB, src, dst_table, alice_tuple_cnt, false);
        }
    }
    netio_->flush();

    return dst_table;


}

#include <chrono>
#include <iomanip>

// ...

std::vector<emp::Integer> SH2PCManager::runInCircuitDecryption(
        const std::vector<int64_t>& partial_b,
        const std::vector<int64_t>& partial_c,
        const std::vector<int64_t>& mask_b,
        const std::vector<int64_t>& mask_c,
        uint64_t modulus) {

    if (partial_b.size() != partial_c.size()) {
        throw std::runtime_error("runInCircuitDecryption: partial vector size mismatch");
    }
    if (mask_b.size() != mask_c.size() || mask_b.size() != partial_b.size()) {
        throw std::runtime_error("runInCircuitDecryption: mask vector size mismatch");
    }

    const size_t size = partial_b.size();
    const int bit_len = 64;

    // Handshake to ensure both parties enter before heavy compute.
    bool sync_ready = true;
    if (party_ == emp::ALICE) {
        netio_->send_data(&sync_ready, 1);
        netio_->flush();
        netio_->recv_data(&sync_ready, 1);
    } else {
        netio_->recv_data(&sync_ready, 1);
        netio_->send_data(&sync_ready, 1);
        netio_->flush();
    }

    emp::Integer q(bit_len, static_cast<long long>(modulus), emp::PUBLIC);

    std::vector<emp::Integer> decrypted_res;
    decrypted_res.reserve(size);

    // DEBUG: set to size for full run; smaller for quick checks.
    const size_t debug_limit = size;

    using clock = std::chrono::steady_clock;
    const auto t_start = clock::now();

    std::cout << "[MPC Manager] runInCircuitDecryption start: coeffs=" << debug_limit
              << " bit_len=" << bit_len
              << " q=" << modulus
              << std::endl;

    // Print progress every N iterations (avoid too frequent I/O)
    const size_t kProgressStep = 10000; // change to 1000 if you want finer granularity

    for (size_t i = 0; i < debug_limit; ++i) {

        if (i > 0 && (i % kProgressStep == 0)) {
            const auto now = clock::now();
            const double elapsed = std::chrono::duration<double>(now - t_start).count();
            const double rate = static_cast<double>(i) / std::max(1e-9, elapsed); // iters/sec
            const double remain = static_cast<double>(debug_limit - i);
            const double eta = remain / std::max(1e-9, rate);

            std::cout << "[MPC] progress " << i << " / " << debug_limit
                      << " (" << std::fixed << std::setprecision(2)
                      << (100.0 * i / debug_limit) << "%)"
                      << " elapsed=" << elapsed << "s"
                      << " rate=" << rate << " it/s"
                      << " eta~" << eta << "s"
                      << std::endl;
        }

        const int64_t b_val = partial_b[i];
        const int64_t c_val = partial_c[i];
        const int64_t b_mask = mask_b[i];
        const int64_t c_mask = mask_c[i];

        emp::Integer val_b(bit_len, (party_ == emp::ALICE) ? static_cast<long long>(b_val) : 0, emp::ALICE);
        emp::Integer val_c(bit_len, (party_ == emp::BOB) ? static_cast<long long>(c_val) : 0, emp::BOB);
        emp::Integer m_b(bit_len, (party_ == emp::ALICE) ? static_cast<long long>(b_mask) : 0, emp::ALICE);
        emp::Integer m_c(bit_len, (party_ == emp::BOB) ? static_cast<long long>(c_mask) : 0, emp::BOB);

        emp::Integer w_masked = (val_b + val_c + m_b + m_c) % q;
        decrypted_res.push_back(w_masked);
    }

    netio_->flush();

    const auto t_end = clock::now();
    const double total = std::chrono::duration<double>(t_end - t_start).count();
    const double rate_total = static_cast<double>(debug_limit) / std::max(1e-9, total);

    std::cout << "[MPC Manager] runInCircuitDecryption done: coeffs=" << debug_limit
              << " total=" << std::fixed << std::setprecision(3) << total << "s"
              << " avg_rate=" << std::setprecision(2) << rate_total << " it/s"
              << std::endl;

    return decrypted_res;
}

void SH2PCManager::secret_share_recv(const size_t &tuple_count, const int &party,
                                    SecureTable *dst_table, const size_t &write_offset,
                                    const bool &reverse_read_order)  {

    int32_t cursor = (int32_t) write_offset;
    auto dst_schema = dst_table->getSchema();
    auto src_schema = QuerySchema::toPlain(dst_schema);

    PlainTuple src_tuple(&src_schema);

    if(reverse_read_order) {

        for(int32_t i = tuple_count - 1; i >= 0; --i) {
            for(int j = 0; j < dst_table->getSchema().getFieldCount(); ++j) {
                PlainField placeholder = src_tuple.getField(j);
                auto field_desc = dst_schema.getField(j);
                auto dst_field = SecureField::secretShareHelper(placeholder, field_desc, party, false);
                dst_table->setField(cursor, j, dst_field);
            }

            emp::Bit b(0, party);
            dst_table->setDummyTag(cursor, b);
            ++cursor;
        }
        return;
    }

    // else
    for(size_t i = 0; i < tuple_count; ++i) {
        for(int j = 0; j < dst_table->getSchema().getFieldCount(); ++j) {
            PlainField placeholder = src_tuple.getField(j);
            auto field_desc = dst_schema.getField(j);
            auto dst_field = SecureField::secretShareHelper(placeholder, field_desc, party, false);
            dst_table->setField(cursor, j, dst_field);
        }

        emp::Bit b(0, party);
        dst_table->setDummyTag(cursor, b);
        ++cursor;
    }

}






void
SH2PCManager::secret_share_send(const int &party,const PlainTable *src_table, SecureTable *dst_table, const int &write_offset,
                               const bool &reverse_read_order)  {

    int cursor = (int) write_offset;
    auto src_schema = src_table->getSchema();
    auto dst_schema = dst_table->getSchema();


    if(reverse_read_order) {
        for(int i = src_table->tuple_cnt_ - 1; i >= 0; --i) {
            for(int j = 0; j < src_table->getSchema().getFieldCount(); ++j) {
                auto src_field = src_table->getField(i, j);
                auto field_desc = dst_schema.getField(j);

                auto dst_field = SecureField::secretShareHelper(src_field, field_desc, party, true);
                dst_table->setField(cursor, j, dst_field);
            }
            emp::Bit b(src_table->getDummyTag(i), party);
            dst_table->setDummyTag(cursor, b);

            ++cursor;
        }
        return; // end reverse order
    }

    // else
    for(size_t i = 0; i < src_table->tuple_cnt_; ++i) {
        for(int j = 0; j < src_table->getSchema().getFieldCount(); ++j) {
            auto src_field = src_table->getField(i, j);
            auto field_desc = dst_schema.getField(j);
            auto dst_field = SecureField::secretShareHelper(src_field, field_desc, party, true);
            dst_table->setField(cursor, j, dst_field);
        }

        emp::Bit b(src_table->getDummyTag(i), party);
        dst_table->setDummyTag(cursor, b);
        ++cursor;
    }

}



#endif
