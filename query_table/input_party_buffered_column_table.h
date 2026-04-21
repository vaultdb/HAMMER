#ifndef _INPUT_PARTY_BUFFERED_COLUMN_TABLE_
#define _INPUT_PARTY_BUFFERED_COLUMN_TABLE_

#include "query_table/buffered_column_table.h"


// substitute for PackedColumnTable if SystemConfiguration::party_ == SystemConfiguration::input_party_
// input party / TP (trusted party) does not need to hold secret shares, instead it produces zero block for every pack/unpack operation
#if  __has_include("emp-sh2pc/emp-sh2pc.h") || __has_include("emp-zk/emp-zk.h")

namespace vaultdb {


    class InputPartyBufferedColumnTable : public BufferedColumnTable {
    public:
         InputPartyBufferedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : BufferedColumnTable(tuple_cnt, schema, sort_def) {}

         InputPartyBufferedColumnTable(const InputPartyBufferedColumnTable & src) : BufferedColumnTable(src) {}


        QueryTable<Bit> *clone()  override {
            return new InputPartyBufferedColumnTable(*this);
        }

        void getPage(const PageId &pid, Bit *dst) override {
            throw;
         }


    };
}
#else
namespace  vaultdb {
    class InputPartyBufferedColumnTable : public BufferedColumnTable {
    public:

        InputPartyBufferedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : BufferedColumnTable(tuple_cnt, schema, sort_def) {
            table_file_handle_ = nullptr; // should not be necessary

        }

        InputPartyBufferedColumnTable(const InputPartyBufferedColumnTable &src) : BufferedColumnTable(src) {
            InputPartyBufferedColumnTable *src_table = const_cast<InputPartyBufferedColumnTable *>(&src);
            bpm_.flushTable(src_table->table_id_);
            table_file_handle_ = nullptr; // should not be necessary

        }

        QueryTable<Bit> *clone()  override {
            return new InputPartyBufferedColumnTable(*this);
        }

        void getPage(const PageId &pid, Bit * dst) override {
            for (int i = 0; i < bpm_.page_size_bits_; i++) {
                dst[i] = Bit(false);
            }
        }

        void flushPage(const PageId &pid, const Bit *bits) {
            // do nothing
        }

    };
}
#endif
#endif //_INPUT_PARTY_BUFFERED_COLUMN_TABLE_
