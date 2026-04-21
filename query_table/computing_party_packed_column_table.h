#ifndef _COMPUTING_PARTY_PACKED_COLUMN_TABLE_
#define _COMPUTING_PARTY_PACKED_COLUMN_TABLE_
#include "query_table/packed_column_table.h"
#include <vector>
#include <string>
#include <filesystem>

#if  __has_include("emp-sh2pc/emp-sh2pc.h") || __has_include("emp-zk/emp-zk.h")
namespace vaultdb {
class ComputingPartyPackedColumnTable : public PackedColumnTable  {
public:
    ComputingPartyPackedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : PackedColumnTable(tuple_cnt, schema, sort_def) { }

    ComputingPartyPackedColumnTable(const ComputingPartyPackedColumnTable &src) : PackedColumnTable(src) {}

    QueryTable<Bit> *clone()  override {
        return new ComputingPartyPackedColumnTable(*this);
    }


};
} // namespace vaultdb


#else
namespace vaultdb {
class ComputingPartyPackedColumnTable : public PackedColumnTable  {
public:
    ComputingPartyPackedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : PackedColumnTable(tuple_cnt, schema, sort_def) {

        // create table file
        table_file_name_ = SystemConfiguration::getInstance().temp_db_path_ + "/table_" + std::to_string(table_id_) + "_wires.p" + std::to_string(SystemConfiguration::getInstance().party_);
        string cmd = "touch " + table_file_name_;
        system(cmd.c_str());

        if(tuple_cnt == 0)
            return;


        OMPCPackedWire zero(bpm_.block_n_);
        vector<int8_t> zero_block = serializePackedWire(zero);
        vector<int8_t> one_block = serializePackedWire(one_wire_);

        assert(zero_block.size() == packed_wire_size_bytes_);

        fopenPackedPagesFile();

        // initialize packed wires
        for(int i = 0; i < schema_.getFieldCount(); ++i) {
            int col_packed_wires = (wires_per_field_.at(i) == 1) ? tuple_cnt_ / fields_per_wire_.at(i) + (tuple_cnt_ % fields_per_wire_.at(i) != 0) : (tuple_cnt_ * wires_per_field_.at(i));

            for(int j = 0; j < col_packed_wires; ++j) {
                fwrite(zero_block.data(), 1, zero_block.size(), packed_pages_file_);
            }
        }

        // initialize dummy tags to true until the row is initialized
        int dummy_tag_packed_wires = tuple_cnt_ / bpm_.page_size_bits_ + ((tuple_cnt_ % bpm_.page_size_bits_) != 0);
        for (int j = 0; j < dummy_tag_packed_wires; ++j) {
            fwrite(one_block.data(), 1, one_block.size(), packed_pages_file_);
        }

        fflush(packed_pages_file_);
    }

    ComputingPartyPackedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const string & src_filename, const int & src_tuple_cnt, const SortDefinition &sort_def = SortDefinition()) : PackedColumnTable(tuple_cnt, schema, sort_def) {
        // create table file
        table_file_name_ = SystemConfiguration::getInstance().temp_db_path_ + "/table_" + std::to_string(table_id_) + "_wires.p" + std::to_string(SystemConfiguration::getInstance().party_);
        string cmd = "touch " + table_file_name_;
        system(cmd.c_str());

        if(tuple_cnt == 0)
            return;

        if(tuple_cnt == src_tuple_cnt) {
            std::filesystem::copy_file(src_filename.c_str(), table_file_name_.c_str(), std::filesystem::copy_options::overwrite_existing);

            fopenPackedPagesFile();
        }

        auto src_ordinal_offsets = getOrdinalOffsets(schema, src_tuple_cnt);

        FILE *src_file = fopen(src_filename.c_str(), "rb");
        fopenPackedPagesFile();

        // initialize packed wires
        for(int i = 0; i < schema.getFieldCount(); ++i) {
            int read_size = PackedColumnTable::bytesPerColumn(schema.getField(i), tuple_cnt);
            vector<int8_t> tmp = vector<int8_t>(read_size, 0);
            fseek(src_file, src_ordinal_offsets.at(i), SEEK_SET); // read read_offset bytes from beginning of file
            fread(tmp.data(), 1, read_size, src_file);
            fwrite(tmp.data(), 1, read_size, packed_pages_file_);
        }

        int read_offset = src_ordinal_offsets.at(-1);
        int read_size = PackedColumnTable::bytesPerColumn(schema.getField(-1), tuple_cnt);
        vector<int8_t> tmp = vector<int8_t>(read_size, 0);
        fseek(src_file, read_offset, SEEK_SET); // read read_offset bytes from beginning of file
        fread(tmp.data(), 1, read_size, src_file);
        fwrite(tmp.data(), 1, read_size, packed_pages_file_);

        fflush(packed_pages_file_);

        fclose(src_file);
    }

    ComputingPartyPackedColumnTable(const ComputingPartyPackedColumnTable &src) : PackedColumnTable(src){

        ComputingPartyPackedColumnTable *src_table = const_cast<ComputingPartyPackedColumnTable *>(&src);
        bpm_.flushTable(src_table->table_id_);
        fflush(src_table->packed_pages_file_);

        table_file_name_ = SystemConfiguration::getInstance().temp_db_path_ + "/table_" + std::to_string(table_id_) + "_wires.p" + std::to_string(SystemConfiguration::getInstance().party_);
        string cmd = "touch " + table_file_name_;
        system(cmd.c_str());

        string src_table_file = src.table_file_name_;
        assert(!src_table_file.empty());

        std::filesystem::copy_file(src_table_file.c_str(), table_file_name_.c_str(), std::filesystem::copy_options::overwrite_existing);

        fopenPackedPagesFile();
    }

    QueryTable<Bit> *clone()  override {
        return new ComputingPartyPackedColumnTable(*this);
    }

    void appendColumn(const QueryFieldDesc & desc) override {

        appendColumnSetup(desc);


        OMPCPackedWire zero(bpm_.block_n_);
        vector<int8_t> zero_block = serializePackedWire(zero);

        int ordinal = desc.getOrdinal();
        int col_packed_wires = (wires_per_field_.at(ordinal) == 1)
            ? tuple_cnt_ / fields_per_wire_.at(ordinal) + (tuple_cnt_ % fields_per_wire_.at(ordinal) != 0)
            : (tuple_cnt_ * wires_per_field_.at(ordinal));

        packed_pages_[ordinal] = std::vector<int8_t>(col_packed_wires * packed_wire_size_bytes_);
        for(int j = 0; j < col_packed_wires; ++j) {
            memcpy(packed_pages_[ordinal].data() + j * packed_wire_size_bytes_, zero_block.data(), packed_wire_size_bytes_);
        }

    }

     void writePackedWire(const PageId & pid, OMPCPackedWire & wire) override {
        int write_offset = getPageOffset(pid);

        fseek(packed_pages_file_, write_offset, SEEK_SET);
        fwrite(reinterpret_cast<int8_t *>(&wire.spdz_tag), block_size_bytes_, 1, packed_pages_file_);
        fwrite(reinterpret_cast<int8_t *>(wire.packed_masked_values.data()), block_size_bytes_ * bpm_.block_n_, 1, packed_pages_file_);
        fwrite(reinterpret_cast<int8_t *>(wire.packed_lambdas.data()), block_size_bytes_ * bpm_.block_n_, 1, packed_pages_file_);
        fflush(packed_pages_file_);
    }

     OMPCPackedWire readPackedWire(const PageId & pid)  const override {
        int read_offset = getPageOffset(pid);

         fseek(packed_pages_file_, read_offset, SEEK_SET); // read read_offset bytes from beginning of file
         vector<int8_t> dst = vector<int8_t>(packed_wire_size_bytes_, 0);
         fread(dst.data(), 1, packed_wire_size_bytes_, packed_pages_file_);

         return deserializePackedWire(dst.data());
    }

    void getPage(const PageId &pid, Bit *dst) override {
        OMPCPackedWire src = readPackedWire(pid);
        manager_->unpack((Bit *) &src, dst, bpm_.page_size_bits_);
    }

    void flushPage(const PageId &pid, Bit *src) override {
        OMPCPackedWire wire(bpm_.block_n_);
        manager_->pack(src, (Bit *) &wire, bpm_.page_size_bits_);
        writePackedWire(pid, wire);
    }

    void resize(const size_t &tuple_cnt) override {
        if(tuple_cnt == this->tuple_cnt_) return;

        bpm_.flushTable(this->table_id_);

        int old_tuple_cnt = this->tuple_cnt_;

        this->tuple_cnt_ = tuple_cnt;

        map<int, vector<int8_t> > new_packed_pages;


        int rows_to_cp = (tuple_cnt >= old_tuple_cnt) ? old_tuple_cnt : tuple_cnt;

        for (int i = 0; i < schema_.getFieldCount(); ++i) {
            int fields_per_wire = fields_per_wire_.at(i);
            int wires_needed = tuple_cnt / fields_per_wire + (tuple_cnt % fields_per_wire != 0);

            new_packed_pages[i] = vector<int8_t>(wires_needed * packed_wire_size_bytes_);

            // copy over old data
            int wires_to_cp = rows_to_cp / fields_per_wire + (rows_to_cp % fields_per_wire != 0);
            auto src = packed_pages_.at(i).data();
            auto dst = new_packed_pages.at(i).data();
            memcpy(dst, src, wires_to_cp * packed_wire_size_bytes_);
        }

        // copy over dummy tag
        int wires_to_cp = rows_to_cp / bpm_.page_size_bits_ + (rows_to_cp % bpm_.page_size_bits_ != 0);
        new_packed_pages[-1] = vector<int8_t>(wires_to_cp * packed_wire_size_bytes_);
        auto src = packed_pages_.at(-1).data();
        auto dst = new_packed_pages.at(-1).data();
        memcpy(dst, src, wires_to_cp * packed_wire_size_bytes_);

        // replace the old setup
        packed_pages_ = new_packed_pages;

    }

private:
    inline int getPageOffset(const PageId &pid) const {
        return ordinal_offsets_.at(pid.col_id_) + pid.page_idx_ * packed_wire_size_bytes_;
    }

    inline int fopenPackedPagesFile() {
        packed_pages_file_ = fopen(table_file_name_.c_str(), "r+b");
        if (!packed_pages_file_) {
            throw std::runtime_error(
                    std::string("Failed to open file '") + table_file_name_ + "': " + strerror(errno)
            );
        }
    }


};
} // namespace vaultdb

#endif

#endif