#ifndef _INPUT_PARTY_PACKED_COLUMN_TABLE_
#define _INPUT_PARTY_PACKED_COLUMN_TABLE_

#include "query_table/packed_column_table.h"


// substitute for PackedColumnTable if SystemConfiguration::party_ == SystemConfiguration::input_party_
// input party / TP (trusted party) does not need to hold secret shares, instead it produces zero block for every pack/unpack operation
#if  __has_include("emp-sh2pc/emp-sh2pc.h") || __has_include("emp-zk/emp-zk.h")

namespace vaultdb {


    class InputPartyPackedColumnTable : public PackedColumnTable {
    public:
         InputPartyPackedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : PackedColumnTable(tuple_cnt, schema, sort_def) {}

         InputPartyPackedColumnTable(const InputPartyPackedColumnTable & src) : PackedColumnTable(src) {}


        QueryTable<Bit> *clone()  override {
            return new InputPartyPackedColumnTable(*this);
        }



    };
}
#else
namespace  vaultdb {
    class InputPartyPackedColumnTable : public PackedColumnTable {
    public:

        InputPartyPackedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : PackedColumnTable(tuple_cnt, schema, sort_def) {
            zero_block_ = OMPCPackedWire(bpm_.block_n_);
            zero_ = Bit(0);
            packed_pages_file_ = nullptr;

        }

        InputPartyPackedColumnTable(const InputPartyPackedColumnTable &src) : PackedColumnTable(src) {
            InputPartyPackedColumnTable *src_table = const_cast<InputPartyPackedColumnTable *>(&src);
            bpm_.flushTable(src_table->table_id_);
            zero_block_ = src_table->zero_block_;
            zero_ = src_table->zero_;
            packed_pages_file_ = nullptr;
        }

        QueryTable<Bit> *clone()  override {
            return new InputPartyPackedColumnTable(*this);
        }


        OMPCPackedWire readPackedWire(const PageId & pid) const  override {
            return zero_block_;
        }

        void writePackedWire(const PageId & pid, OMPCPackedWire & wire) override {
            // do nothing
        }


        void getPage(const PageId &pid, Bit *dst) override {

            for (int i = 0; i < bpm_.page_size_bits_; ++i) {
                dst[i] = zero_;
            }

            bpm_.emp_manager_->unpack((Bit *) &zero_block_, dst, bpm_.page_size_bits_);
            // cout << "Page raw bits: " << DataUtilities::printByteArray((int8_t *) dst, 16) << endl;
            // cout << "Page starts with " << DataUtilities::revealAndPrintFirstBits(dst, 16) << endl;

        }

        void flushPage(const PageId &pid, Bit *src) override {
            // cout << "Page raw bits: " << DataUtilities::printByteArray((int8_t *) src, 16) << endl;
            // cout << "Page starts with " << DataUtilities::revealAndPrintFirstBits(src, 16) << endl;

            OMPCPackedWire wire(bpm_.block_n_);
            bpm_.emp_manager_->pack(src,  (Bit *) &wire, bpm_.page_size_bits_);

        }

        void resize(const size_t &tuple_cnt) override {
            if(tuple_cnt != this->tuple_cnt_) {
                bpm_.flushTable(this->table_id_);
            }

            tuple_cnt_ = tuple_cnt;
        }

        void appendColumn(const QueryFieldDesc & desc) override {
            appendColumnSetup(desc);
        }


    private:
        OMPCPackedWire zero_block_;
        Bit zero_;
    };
}
#endif
#endif //_INPUT_PARTY_PACKED_COLUMN_TABLE_
