#include "query_table/column_table.h"
#include "query_table/plain_tuple.h"
#include "query_table/secure_tuple.h"
#include "query_table/query_schema.h"
#include "query_table/field/field.h"
#include "query_table/field/field_type.h"
#include "util/field_utilities.h"
#include "util/type_utilities.h"
#include <iostream>
#include <stdexcept>

using namespace vaultdb;

template<>
void ColumnTable<bool>::cloneRow(const bool & write, const int & dst_row, const int & dst_col, const QueryTable<bool> *src, const int & src_row)  {
    if(write)
        cloneRow(dst_row, dst_col, src, src_row);
}

template<>
void ColumnTable<Bit>::cloneRow(const Bit & write, const int & dst_row, const int & dst_col, const QueryTable<Bit> *s, const int & src_row)  {

    assert(s->storageModel() == StorageModel::COLUMN_STORE);
    auto src = (ColumnTable<Bit> *) s;

    int write_idx = dst_col; // field indexes
    int read_idx = 0;
    int bytes_read = 0;

    while(read_idx < src->schema_.getFieldCount()) {
        Bit *write_pos = reinterpret_cast<Bit *>(getFieldPtr(dst_row, write_idx));
        Bit *read_pos = reinterpret_cast<Bit *>(src->getFieldPtr(src_row, read_idx));
        int to_read_bits = this->field_sizes_bytes_[write_idx] / sizeof(emp::Bit);
        for(int i = 0; i <  to_read_bits; ++i) {
            *write_pos = emp::If(write, *read_pos, *write_pos);
            ++write_pos;
            ++read_pos;
        }
        ++read_idx;
        ++write_idx;
    }

    // copy dummy tag
    Bit *write_pos = reinterpret_cast<Bit *>(getFieldPtr(dst_row, -1));
    Bit *read_pos = reinterpret_cast<Bit *>(src->getFieldPtr(src_row, -1));
    *write_pos = emp::If(write, *read_pos, *write_pos);
}

template <>
void ColumnTable<bool>::setRow(const int &idx, const QueryTuple<bool> &tuple) {
    auto read_pos = tuple.getData();

    for(int i = 0; i < schema_.getFieldCount(); ++i) {
        auto write_pos = getFieldPtr(idx, i);
        memcpy(write_pos, read_pos, field_sizes_bytes_[i]);
        read_pos += field_sizes_bytes_[i];
    }

    // dummy tag
    auto write_pos = getFieldPtr(idx, -1);
    memcpy(write_pos, read_pos, field_sizes_bytes_[-1]);
}

template<>
void ColumnTable<Bit>::setRow(const int &idx, const QueryTuple<Bit> &tuple) {
    auto read_pos = tuple.getData();
    int row_bits = schema_.size();
    emp::Integer i_tuple(row_bits, 0L);
    memcpy(i_tuple.bits.data(), read_pos, row_bits * sizeof(emp::Bit));
    packRow(idx, i_tuple);
}

template<>
void ColumnTable<bool>::compareSwap(const bool &swap, const int &lhs_row, const int &rhs_row) {
    if(swap) {
        // iterating on column_data to cover dummy tag at -1
        for(auto pos : column_data_) {
            int col_id = pos.first;
            int8_t *l = getFieldPtr(lhs_row, col_id);
            int8_t *r = getFieldPtr(rhs_row, col_id);

            // swap in place
            for(int i = 0; i < field_sizes_bytes_[col_id]; ++i) {
                *l = *l ^ *r;
                *r = *r ^ *l;
                *l = *l ^ *r;

                ++l;
                ++r;
            }

        }
    }
}

template<>
void ColumnTable<Bit>::compareSwap(const Bit &swap, const int &lhs_row, const int &rhs_row) {

    int col_cnt = schema_.getFieldCount();

    for(int col_id = 0; col_id < col_cnt; ++col_id) {

        int field_len = schema_.fields_.at(col_id).size();
        Bit *l = reinterpret_cast<Bit *>(getFieldPtr(lhs_row, col_id));
        Bit *r = reinterpret_cast<Bit *>(getFieldPtr(rhs_row, col_id));

        for(int i = 0; i < field_len; ++i) {
            emp::swap(swap, l[i], r[i]);
        }

    }
    // dummy tag
    Bit *l = reinterpret_cast<Bit *>(getFieldPtr(lhs_row, -1));
    Bit *r = reinterpret_cast<Bit *>(getFieldPtr(rhs_row, -1));
    Bit o = emp::If(swap, *l, *r);
    o ^= *r;
    *l ^= o;
    *r ^= o;

}

template<>
SecureTable *ColumnTable<bool>::secretShareAdditive(const int & my_party) {
    if (this->isEncrypted()) {
        throw std::runtime_error("secretShareAdditive: cannot share an already encrypted table.");
    }
    QuerySchema dst_schema = QuerySchema::toSecure(this->schema_);
    auto dst_table = QueryTable<emp::Bit>::getTable(this->tuple_cnt_, dst_schema, this->order_by_);

    for (size_t i = 0; i < this->tuple_cnt_; ++i) {
        bool my_dummy = this->getDummyTag(static_cast<int>(i));
        emp::Bit dummy_A((my_party == emp::ALICE ? my_dummy : false), emp::ALICE);
        emp::Bit dummy_B((my_party == emp::BOB   ? my_dummy : false), emp::BOB);
        dst_table->setDummyTag(static_cast<int>(i), dummy_A ^ dummy_B);

        for (int j = 0; j < this->schema_.getFieldCount(); ++j) {
            PlainField my_field = this->getField(static_cast<int>(i), j);
            const QueryFieldDesc & desc = dst_schema.getField(j);

            int64_t val = 0;
            double f_val = 0.0;
            switch (my_field.getType()) {
                case FieldType::LONG:
                    val = my_field.getValue<int64_t>();
                    break;
                case FieldType::INT:
                    val = static_cast<int64_t>(my_field.getValue<int32_t>());
                    break;
                case FieldType::BOOL:
                    val = my_field.getValue<bool>() ? 1 : 0;
                    break;
                case FieldType::FLOAT:
                    f_val = static_cast<double>(my_field.getValue<float_t>());
                    val = 0;
                    break;
                case FieldType::STRING: {
                    std::string s = my_field.getString();
                    if (!s.empty()) val = static_cast<int64_t>(static_cast<unsigned char>(s[0]));
                    break;
                }
                default:
                    break;
            }

            if (desc.getType() == FieldType::SECURE_BOOL) {
                bool b = (val != 0);
                emp::Bit bit_A((my_party == emp::ALICE ? b : false), emp::ALICE);
                emp::Bit bit_B((my_party == emp::BOB   ? b : false), emp::BOB);
                SecureField sf(desc.getType(), bit_A ^ bit_B);
                dst_table->setField(static_cast<int>(i), j, sf);
            } else if (desc.getType() == FieldType::SECURE_FLOAT) {
                double share_val = (my_party == emp::ALICE || my_party == emp::BOB) ? f_val : 0.0;
                emp::Float val_A((my_party == emp::ALICE ? share_val : 0.0), emp::ALICE);
                emp::Float val_B((my_party == emp::BOB   ? share_val : 0.0), emp::BOB);
                SecureField sf(desc.getType(), val_A + val_B);
                dst_table->setField(static_cast<int>(i), j, sf);
            } else if (desc.getType() == FieldType::SECURE_INT || desc.getType() == FieldType::SECURE_LONG ||
                       desc.getType() == FieldType::SECURE_STRING) {
                int bit_len = static_cast<int>(desc.size()) + (desc.bitPacked() ? 1 : 0);
                if (bit_len <= 0) bit_len = 64;
                // Step 5: B inputs Val_B=R (ALICE), C inputs Val_C=M-R (BOB). Same protocol run on both sides.
                emp::Integer val_A(bit_len, (my_party == emp::ALICE ? val : 0), emp::ALICE);
                emp::Integer val_B(bit_len, (my_party == emp::BOB   ? val : 0), emp::BOB);
                // Secure_Sum = Share(Val_C) + Share(Val_B); Reveal(Secure_Sum) = M. Arithmetic (+) for carry.
                emp::Integer res = val_A + val_B;
                SecureField sf(desc.getType(), res);
                dst_table->setField(static_cast<int>(i), j, sf);
            } else {
                throw std::runtime_error("secretShareAdditive: unsupported secure field type for column " + std::to_string(j) + " name=" + desc.getName() + " type=" + TypeUtilities::getTypeName(desc.getType()));
            }
        }
    }
    return dst_table;
}

template<>
SecureTable *ColumnTable<emp::Bit>::secretShareAdditive(const int &) {
    throw std::runtime_error("secretShareAdditive: only plain tables supported.");
}

template class vaultdb::ColumnTable<bool>;
template class vaultdb::ColumnTable<emp::Bit>;
