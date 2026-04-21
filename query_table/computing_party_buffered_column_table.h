#ifndef _COMPUTING_PARTY_BUFFERED_COLUMN_TABLE_
#define _COMPUTING_PARTY_BUFFERED_COLUMN_TABLE_
#include "query_table/packed_column_table.h"
#include <vector>
#include <string>
#include <bits/fs_fwd.h>
#include <bits/fs_path.h>

#if  __has_include("emp-sh2pc/emp-sh2pc.h") || __has_include("emp-zk/emp-zk.h")
namespace vaultdb {
class ComputingPartyBufferedColumnTable : public BufferedColumnTable  {
public:
    ComputingPartyBufferedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : BufferedColumnTable(tuple_cnt, schema, sort_def) { }

    ComputingPartyBufferedColumnTable(const ComputingPartyBufferedColumnTable &src) : BufferedColumnTable(src) {}

    QueryTable<Bit> *clone()  override {
        return new ComputingPartyBufferedColumnTable(*this);
    }

    void getPage(const PageId &pid, Bit *dst) override {
        throw;
    }




};
} // namespace vaultdb


#else
namespace vaultdb {
class ComputingPartyBufferedColumnTable : public BufferedColumnTable  {
public:
    ComputingPartyBufferedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const string & src_filename, const int & src_tuple_cnt, const SortDefinition &sort_def = SortDefinition())
    : BufferedColumnTable(tuple_cnt, schema, sort_def) {
        if(tuple_cnt == 0)
            return;

        ordinal_offsets_ = getOrdinalOffsets(schema_, tuple_cnt);
        auto src_ordinal_offsets = getOrdinalOffsets(schema_, src_tuple_cnt);

        // find size of original file, if we are truncating then create a shadow copy that is shorter

        if (tuple_cnt == src_tuple_cnt) {
            filename_ = src_filename;
            table_file_handle_ = fopen(filename_.c_str(), "rb"); // read-only because this is a leaf node
            return; // no need to truncate, just read the original file
        }

        FILE *src_file = fopen(src_filename.c_str(), "rb");

        // set up file handle
        filename_ = SystemConfiguration::getInstance().temp_db_path_ + "/" + std::to_string(table_id_) + ".p" + std::to_string(SystemConfiguration::getInstance().party_) +  ".pages";
        string cmd = "touch " + filename_;
        system(cmd.c_str());
        table_file_handle_ = fopen(filename_.c_str(), "r+b"); // rwb


        // initialize  pages
        // TODO: rewrite this using the buffer pool!
        for(int i = 0; i < schema_.getFieldCount(); ++i) {
            int read_size = PackedColumnTable::bytesPerColumn(schema_.getField(i), tuple_cnt);
            vector<int8_t> tmp = vector<int8_t>(read_size, 0);
            fseek(src_file, src_ordinal_offsets.at(i), SEEK_SET); // read read_offset bytes from beginning of file
            fread(tmp.data(), 1, read_size, src_file);
            fwrite(tmp.data(), 1, read_size, table_file_handle_);
        }

        int read_offset = src_ordinal_offsets.at(-1);
        int read_size = PackedColumnTable::bytesPerColumn(schema_.getField(-1), tuple_cnt);
        vector<int8_t> tmp = vector<int8_t>(read_size, 0);
        fseek(src_file, read_offset, SEEK_SET); // read read_offset bytes from beginning of file
        fread(tmp.data(), 1, read_size, src_file);
        fwrite(tmp.data(), 1, read_size, table_file_handle_);

        fflush(table_file_handle_);

        fclose(src_file);
    }


    ComputingPartyBufferedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : BufferedColumnTable(tuple_cnt, schema, sort_def) {

        // set up file handle
        filename_ = SystemConfiguration::getInstance().temp_db_path_ + "/" + std::to_string(table_id_) + ".p" + std::to_string(SystemConfiguration::getInstance().party_) +  ".pages";
        string cmd = "touch " + filename_;
        system(cmd.c_str());

        if(tuple_cnt == 0)
            return;

        vector<Bit> zero_page(bpm_.page_size_bits_, Bit(false));
        vector<int8_t> zero_bytes(bpm_.page_size_bits_ * sizeof(Bit), 0);

        vector<Bit> one_page(bpm_.page_size_bits_, Bit(true));
        vector<int8_t> one_bytes(bpm_.page_size_bits_ * sizeof(Bit), 0);


        memcpy(zero_bytes.data(), zero_page.data(), zero_page.size() * sizeof(Bit));

        table_file_handle_ = fopen(filename_.c_str(), "r+b"); // rwb

        ordinal_offsets_ = getOrdinalOffsets(schema_, tuple_cnt);


        // initialize packed wires
        for(int i = 0; i < schema_.getFieldCount(); ++i) {
            int page_cnt = tuple_cnt / fields_per_page_.at(i) + (tuple_cnt % fields_per_page_.at(i) != 0);
            for (int j = 0; j < page_cnt; ++j) {
                fwrite(zero_bytes.data(),  zero_bytes.size(), 1, table_file_handle_);
            }
        }

        // initialize dummy tags to true until the row is initialized
        int dummy_tag_page_cnt = tuple_cnt_ / bpm_.page_size_bits_ + ((tuple_cnt_ % bpm_.page_size_bits_) != 0);
        for (int j = 0; j < dummy_tag_page_cnt; ++j) {
            fwrite(one_bytes.data(), one_bytes.size(), 1, table_file_handle_);
        }

        fflush(table_file_handle_);
    }

    ComputingPartyBufferedColumnTable(const ComputingPartyBufferedColumnTable &src) : BufferedColumnTable(src){

        ComputingPartyBufferedColumnTable *src_table = const_cast<ComputingPartyBufferedColumnTable *>(&src);
        bpm_.flushTable(src_table->table_id_);

        filename_ = SystemConfiguration::getInstance().temp_db_path_ + "/" + std::to_string(table_id_) + ".p" + std::to_string(SystemConfiguration::getInstance().party_) +  ".pages";

        string src_table_file = src.filename_;

        assert(!src_table_file.empty());
        std::filesystem::copy_file(src_table_file.c_str(), filename_.c_str(), std::filesystem::copy_options::overwrite_existing);
        table_file_handle_ = fopen(filename_.c_str(), "r+b"); // rwb

    }

    QueryTable<Bit> *clone()  override {
        return new ComputingPartyBufferedColumnTable(*this);
    }

    void getPage(const PageId &pid, Bit *dst)  override {
        int offset = this->getPageOffset(pid);
        cout << "reading page " << pid.toString() << " from offset " << offset << endl;
        fseek(table_file_handle_, offset, SEEK_SET);
        fread(dst, sizeof(Bit), bpm_.page_size_bits_, table_file_handle_);
    }

    void flushPage(const PageId &pid, const Bit *bits) override {
        int offset = this->getPageOffset(pid);
        cout << "Flushing page: " << pid.toString() << " to offset " << offset <<  endl;
        fseek(table_file_handle_, offset, SEEK_SET);
        fwrite(bits, sizeof(Bit), bpm_.page_size_bits_, table_file_handle_);
        fflush(table_file_handle_);
    }

private:

    inline int getPageOffset(const PageId & pid) const {
        return ordinal_offsets_.at(pid.col_id_) + pid.page_idx_ * bpm_.page_size_bits_ * sizeof(Bit);
    }

    inline size_t getTableSizeBytes(int tuple_cnt) const {
        size_t array_byte_cnt = 0;
        for(int i = 0; i < schema_.getFieldCount(); ++i) {
            array_byte_cnt += PackedColumnTable::bytesPerColumn(schema_.getField(i), tuple_cnt);
        }
        array_byte_cnt += PackedColumnTable::bytesPerColumn(schema_.getField(-1), tuple_cnt);
        return array_byte_cnt;
    }



    };
} // namespace vaultdb

#endif

#endif
