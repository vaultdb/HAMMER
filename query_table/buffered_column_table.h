#ifndef _BUFFERED_COLUMN_DATA_H_
#define _BUFFERED_COLUMN_DATA_H_
#include "query_table/query_table.h"
#include <filesystem>
#include "query_table/secure_tuple.h"

#if  __has_include("emp-sh2pc/emp-sh2pc.h") || __has_include("emp-zk/emp-zk.h")

namespace vaultdb {
    class BufferedColumnTable : public QueryTable<Bit> {
        public:
            SystemConfiguration &conf_ = SystemConfiguration::getInstance();
            int table_id_ = conf_.num_tables_++;
            std::string file_path_ = this->conf_.stored_db_path_ + "/table_" + std::to_string(this->table_id_);
            std::string secret_shares_path_ = this->file_path_ + "/table_" + std::to_string(this->table_id_) + "." + std::to_string(this->conf_.party_);
            int current_emp_bit_size_on_disk_ = 0;
            std::map<int, int64_t> serialized_col_bytes_offsets_on_disk_;

            std::map<int, int> fields_per_page_;
            std::map<int, int> pages_per_field_;
            std::map<int, int> pages_per_col;

            BufferedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : QueryTable<Bit>(tuple_cnt, schema, sort_def) {}

            BufferedColumnTable(const BufferedColumnTable &src) : QueryTable<Bit>(src) {}

      void getPage(const PageId &pid, Bit *bit) override {
                
            }

            void flushPage(const PageId &pid, Bit *bit) override {
                
            }

            Field<Bit> getField(const int &row, const int &col) const override {
                return Field<Bit>();
            }

            inline void setField(const int &row, const int &col, const Field<Bit> &f) override {}

            SecureTable *secretShare() override  {
                assert(this->isEncrypted());
                throw; // can't secret share already encrypted table
            }

            void appendColumn(const QueryFieldDesc & desc) override {}

            void resize(const size_t &tuple_cnt) override {}

            Bit getDummyTag(const int & row)  const override {
                return emp::Bit(0);
            }

            void setDummyTag(const int & row, const Bit & val) override {}

            QueryTable<Bit> *clone() override {
                return new BufferedColumnTable(*this);
            }

            void setSchema(const QuerySchema &schema) override {}

            QueryTuple<Bit> getRow(const int & idx) override {
                return QueryTuple<Bit>();
            }

            void setRow(const int & idx, const QueryTuple<Bit> &tuple) override {}

            void compareSwap(const Bit & swap, const int  & lhs_row, const int & rhs_row) override {}

            void cloneTable(const int & dst_row, const int & dst_col, QueryTable<Bit> *src) override {}

            void cloneRow(const int & dst_row, const int & dst_col, const QueryTable<Bit> * src, const int & src_row) override {}

            void cloneRow(const Bit & write, const int & dst_row, const int & dst_col, const QueryTable<Bit> *src, const int & src_row) override {}

            void cloneRowRange(const int & dst_row, const int & dst_col, const QueryTable<Bit> *src, const int & src_row, const int & copies) override {}

            void cloneColumn(const int & dst_col, const QueryTable<Bit> *src_table, const int &src_col) override {}

            void cloneColumn(const int & dst_col, const int & dst_row, const QueryTable<Bit> *src, const int & src_col, const int & src_row = 0) override {}

            StorageModel storageModel() const override { return StorageModel::COLUMN_STORE; }

            void deserializeRow(const int & row, vector<int8_t> & src) override {}

            std::vector<emp::Bit> readSecretSharedPageFromDisk(const PageId pid);

            std::vector<emp::Bit> readSecretSharedPageFromDisk(const PageId pid, const int tuple_cnt, const QuerySchema &schema, const int src_col, const string &src_data_path);

            std::vector<int8_t> convertEMPBitToWriteBuffer(const std::vector<emp::Bit> bits);

            void writePageToDisk(const PageId &pid, const emp::Bit *bits);

            ~BufferedColumnTable() {}
    };
}

#else
namespace vaultdb {
    class BufferedColumnTable : public QueryTable<Bit> {
    public:
        SystemConfiguration &conf_ = SystemConfiguration::getInstance();
        int table_id_ = conf_.num_tables_++;
        std::string file_path_ = this->conf_.stored_db_path_ + "/table_" + std::to_string(this->table_id_);
        std::string secret_shares_path_ = this->file_path_ + "/table_" + std::to_string(this->table_id_) + "." + std::to_string(this->conf_.party_);
        int current_emp_bit_size_on_disk_ = (this->conf_.party_ == 1 ? empBitSizesInPhysicalBytes::evaluator_disk_size_ : (this->conf_.party_ == 10086 ? 1 : empBitSizesInPhysicalBytes::garbler_disk_size_));
        std::map<int, int64_t> serialized_col_bytes_offsets_on_disk_; // bytes offsets for each column in the serialized file

        std::map<int, int> fields_per_page_;
        std::map<int, int> pages_per_field_;
        std::map<int, int> pages_per_col;

        BufferedColumnTable(const size_t &tuple_cnt, const QuerySchema &schema, const SortDefinition &sort_def = SortDefinition()) : QueryTable<Bit>(tuple_cnt, schema, sort_def) {
            assert(this->conf_.storageModel() == this->storageModel() && this->conf_.buffer_pool_enabled_);
            setSchema(schema);

            if(this->tuple_cnt_ == 0) {
                return;
            }

            std::filesystem::remove_all(this->secret_shares_path_);
            Utilities::mkdir(this->file_path_);

            // initialize the secret shares file with zeros
            std::vector<int8_t> initialized_bytes(this->tuple_cnt_ * (this->schema_.size() - 1) * current_emp_bit_size_on_disk_, 0);
            // initialize the dummy tag column with ones
            std::vector<emp::Bit> dummy_tags(this->tuple_cnt_, emp::Bit(1));
            std::vector<int8_t> serialized_dummy_tags = this->convertEMPBitToWriteBuffer(dummy_tags);
            initialized_bytes.insert(initialized_bytes.end(), serialized_dummy_tags.begin(), serialized_dummy_tags.end());
            DataUtilities::writeFile(this->secret_shares_path_, initialized_bytes);

            this->conf_.bpm_.registerTable(this->table_id_, (QueryTable<Bit> *) this);
        }

        BufferedColumnTable(const BufferedColumnTable &src) : QueryTable<Bit>(src) {
            assert(src.isEncrypted() && this->isEncrypted() && src.conf_.storageModel() == src.storageModel() && this->conf_.storageModel() == this->storageModel() && this->conf_.buffer_pool_enabled_);
            setSchema(src.schema_);

            if(src.tuple_cnt_ == 0) {
                return;
            }

            std::filesystem::remove_all(this->secret_shares_path_);
            Utilities::mkdir(this->file_path_);

            // initialize the secret shares file with zeros
            std::vector<int8_t> initialized_bytes(this->tuple_cnt_ * (this->schema_.size() - 1) * current_emp_bit_size_on_disk_, 0);
            // initialize the dummy tag column with ones
            std::vector<emp::Bit> dummy_tags(this->tuple_cnt_, emp::Bit(1));
            std::vector<int8_t> serialized_dummy_tags = this->convertEMPBitToWriteBuffer(dummy_tags);
            initialized_bytes.insert(initialized_bytes.end(), serialized_dummy_tags.begin(), serialized_dummy_tags.end());
            DataUtilities::writeFile(this->secret_shares_path_, initialized_bytes);

            this->conf_.bpm_.flushTable(src.table_id_);

            // Why does the direct copy not work?
            //std::filesystem::copy_file(src.secret_shares_path_, this->secret_shares_path_, std::filesystem::copy_options::overwrite_existing);

            this->conf_.bpm_.registerTable(this->table_id_, (QueryTable<Bit> *) this);

            this->cloneTable(0, 0, (QueryTable<Bit> *) &src);
        }



        void getPage(const PageId &pid, Bit *dst) override {
            auto src_bytes = this->readSecretSharedPageFromDisk(pid);
            memcpy(dst, src_bytes.data(), src_bytes.size() * sizeof(emp::Bit));
        }



        Field<Bit> getField(const int &row, const int &col) const override {
            assert(this->isEncrypted() && this->conf_.buffer_pool_enabled_);

            QueryFieldDesc desc = this->schema_.getField(col);

            int field_blocks = this->pages_per_field_.at(col);

            if(field_blocks == 1) {
                PageId pid(this->table_id_, col, row / this->fields_per_page_.at(col));
                emp::Bit *read_ptr = this->conf_.bpm_.getPagePtr(pid) + (row % this->fields_per_page_.at(col)) * desc.size();
                return Field<Bit>::deserialize(desc, (int8_t *) read_ptr);
            }

            throw std::runtime_error("NYI");
        }

        inline void setField(const int &row, const int &col, const Field<Bit> &f) override {
            assert(this->isEncrypted() && this->conf_.buffer_pool_enabled_);

            QueryFieldDesc desc = this->schema_.getField(col);

            int field_blocks = this->pages_per_field_.at(col);

            if(field_blocks == 1) {
                int fields_per_page = this->fields_per_page_.at(col);
                PageId pid = this->conf_.bpm_.getPageId(this->table_id_, col, row, fields_per_page);
                emp::Bit *write_ptr = this->conf_.bpm_.getPagePtr(pid) + (row % fields_per_page) * desc.size();
                f.serialize((int8_t *) write_ptr, f, desc);
                this->conf_.bpm_.markDirty(pid);
                return;
            }

            throw std::runtime_error("NYI");
        }

        SecureTable *secretShare() override  {
            assert(this->isEncrypted());
            throw; // can't secret share already encrypted table
        }

        void appendColumn(const QueryFieldDesc & desc) override {
            int ordinal = desc.getOrdinal();
            assert(ordinal == this->schema_.getFieldCount());

            this->schema_.putField(desc);
            this->schema_.initializeFieldOffsets();

            int field_size_bytes = desc.size() * sizeof(emp::Bit);
            tuple_size_bytes_ += field_size_bytes;
            field_sizes_bytes_[ordinal] = field_size_bytes;

            int size_threshold = conf_.bpm_.page_size_bits_;
            int packed_blocks = desc.size() / size_threshold + (desc.size() % size_threshold != 0);

            if(desc.size() / size_threshold > 0) {
                fields_per_page_[ordinal] = 1;
                pages_per_field_[ordinal] = packed_blocks;
            }
            else {
                fields_per_page_[ordinal] = size_threshold / desc.size();
                pages_per_field_[ordinal] = 1;
            }

            cloneColumn(ordinal, -1, this, ordinal);
        }

        void resize(const size_t &tuple_cnt) override {
            if(tuple_cnt == this->tuple_cnt_) return;

            this->conf_.bpm_.flushTable(this->table_id_);

            int old_tuple_cnt = this->tuple_cnt_;

            this->tuple_cnt_ = tuple_cnt;

            for(int i = 0; i < schema_.getFieldCount(); ++i) {
                int fields_per_wire = fields_per_page_.at(i);

                if(this->tuple_cnt_ > old_tuple_cnt) {
                    int old_pos_in_last_page = old_tuple_cnt % fields_per_wire;

                    if(this->tuple_cnt_ - old_tuple_cnt > fields_per_wire - old_pos_in_last_page - 1) {
                        int rows_to_add = (this->tuple_cnt_ - old_tuple_cnt) - (fields_per_wire - old_pos_in_last_page - 1);

                        int pages_to_add = rows_to_add / fields_per_wire + ((rows_to_add % fields_per_wire) != 0);
                        conf_.bpm_.addPageSequence(table_id_, i, old_tuple_cnt + fields_per_wire - old_pos_in_last_page, pages_to_add, fields_per_wire);
                    }
                }
            }
        }

        Bit getDummyTag(const int & row)  const override {
            assert(this->isEncrypted() && this->conf_.buffer_pool_enabled_);

            int fields_per_page = this->fields_per_page_.at(-1);
            PageId pid = this->conf_.bpm_.getPageId(this->table_id_, -1, row, fields_per_page);
            emp::Bit *read_ptr = this->conf_.bpm_.getPagePtr(pid) + (row % fields_per_page);
            return *read_ptr;
        }

        void setDummyTag(const int & row, const Bit & val) override {
            assert(this->isEncrypted() && this->conf_.buffer_pool_enabled_);

            int fields_per_page = this->fields_per_page_.at(-1);
            PageId pid = this->conf_.bpm_.getPageId(this->table_id_, -1, row, fields_per_page);
            emp::Bit *write_ptr = this->conf_.bpm_.getPagePtr(pid) + (row % fields_per_page);
            *write_ptr = val;
            this->conf_.bpm_.markDirty(pid);
        }

        QueryTable<Bit> *clone() override {
            return new BufferedColumnTable(*this);
        }

        void setSchema(const QuerySchema &schema) override {
            this->schema_ = schema;
            this->plain_schema_ = QuerySchema::toPlain(schema);

            this->tuple_size_bytes_ = 0;

            for(int i = -1; i < this->schema_.getFieldCount(); ++i) {
                QueryFieldDesc desc = this->schema_.getField(i);
                int field_size_bytes = desc.size() * sizeof(emp::Bit);

                this->tuple_size_bytes_ += field_size_bytes;
                this->field_sizes_bytes_[i] = field_size_bytes;

                int bits_per_page = this->conf_.bpm_.page_size_bits_;

                if(desc.size() / bits_per_page > 0) {
                    this->fields_per_page_[i] = 1;
                    this->pages_per_field_[i] = desc.size() / bits_per_page + (desc.size() % bits_per_page != 0);
                }
                else {
                    this->fields_per_page_[i] = bits_per_page / desc.size();
                    this->pages_per_field_[i] = 1;
                }

                this->pages_per_col[i] = this->tuple_cnt_ / this->fields_per_page_[i] + (this->tuple_cnt_ % this->fields_per_page_[i] != 0);
            }

            // calculate offsets for each column in the serialized file
            int64_t col_bytes_cnt = 0L;
            this->serialized_col_bytes_offsets_on_disk_[0] = 0;
            for (int i = 1; i < this->schema_.getFieldCount(); ++i) {
                col_bytes_cnt += this->schema_.getField(i - 1).size() * this->tuple_cnt_ * current_emp_bit_size_on_disk_;
                this->serialized_col_bytes_offsets_on_disk_[i] = col_bytes_cnt;
            }
            col_bytes_cnt += this->schema_.getField(this->schema_.getFieldCount() - 1).size() * this->tuple_cnt_ * current_emp_bit_size_on_disk_;
            this->serialized_col_bytes_offsets_on_disk_[-1] = col_bytes_cnt;
        }

        QueryTuple<Bit> getRow(const int & idx) override {
            SecureTuple tuple(&schema_);
            Bit *write_ptr = (Bit *) tuple.getData();

            for(int i = 0; i < schema_.getFieldCount(); ++i) {
                auto f = getField(idx, i);
                Field<Bit>::serialize((int8_t *) write_ptr, f, schema_.getField(i));
                write_ptr += schema_.getField(i).size();
            }

            Bit dummy_tag = getDummyTag(idx);
            *write_ptr = dummy_tag;

            return tuple;
        }

        void setRow(const int & idx, const QueryTuple<Bit> &tuple) override {
            for(int i = 0; i < schema_.getFieldCount(); ++i) {
                setField(idx, i, tuple.getField(i));
            }

            setDummyTag(idx, tuple.getDummyTag());
        }

        void compareSwap(const Bit & swap, const int  & lhs_row, const int & rhs_row) override {
            for(int col = 0; col < schema_.getFieldCount(); ++col) {
                Integer lhs_int = getField(lhs_row, col).getInt();
                Integer rhs_int = getField(rhs_row, col).getInt();

                emp::swap(swap, lhs_int, rhs_int);

                // write back lhs and rhs
                Field<Bit> lhs_field = Field<Bit>::deserialize(schema_.getField(col), (int8_t *) (lhs_int.bits.data()));
                Field<Bit> rhs_field = Field<Bit>::deserialize(schema_.getField(col), (int8_t *) (rhs_int.bits.data()));

                // set field
                setField(lhs_row, col, lhs_field);
                setField(rhs_row, col, rhs_field);
            }

            // swap dummy tag
            Bit lhs_dummy = getDummyTag(lhs_row);
            Bit rhs_dummy = getDummyTag(rhs_row);
            emp::swap(swap, lhs_dummy, rhs_dummy);

            setDummyTag(lhs_row, lhs_dummy);
            setDummyTag(rhs_row, rhs_dummy);
        }

        void cloneTable(const int & dst_row, const int & dst_col, QueryTable<Bit> *src) override {
            for(int i = 0; i < src->getSchema().getFieldCount(); ++i) {
                for(int j = 0; j < src->tuple_cnt_; ++j) {
                    setField(dst_row + j, dst_col + i, src->getField(j, i));
                    setDummyTag(dst_row + j, src->getDummyTag(j));
                }
            }
        }

        void cloneRow(const int & dst_row, const int & dst_col, const QueryTable<Bit> * src, const int & src_row) override {
            assert(src->storageModel() == StorageModel::COLUMN_STORE);

            for(int i = 0; i < src->getSchema().getFieldCount(); ++i) {
                Field<Bit> f = src->getField(src_row, i);
                this->setField(dst_row, dst_col + i, f);
            }

            this->setDummyTag(dst_row, src->getDummyTag(src_row));
        }

        void cloneRow(const Bit & write, const int & dst_row, const int & dst_col, const QueryTable<Bit> *src, const int & src_row) override {
            assert(src->storageModel() == StorageModel::COLUMN_STORE);

            for(int i = 0; i < src->getSchema().getFieldCount(); ++i) {
                Integer dst_field_int = this->getField(dst_row, dst_col + i).getInt();
                Integer src_field_int = src->getField(src_row, i).getInt();

                Integer write_int = emp::If(write, src_field_int, dst_field_int);

                Field<Bit> write_field = Field<Bit>::deserialize(this->schema_.getField(dst_col + i), (int8_t *) write_int.bits.data());
                this->setField(dst_row, dst_col + i, write_field);
            }

            // copy the dummy tag
            Bit dst_dummy_tag = this->getDummyTag(dst_row);
            Bit src_dummy_tag = src->getDummyTag(src_row);
            this->setDummyTag(dst_row, emp::If(write, src_dummy_tag, dst_dummy_tag));
        }

        void cloneRowRange(const int & dst_row, const int & dst_col, const QueryTable<Bit> *src, const int & src_row, const int & copies) override {
            assert(src->storageModel() == StorageModel::COLUMN_STORE);
            BufferedColumnTable *src_table = (BufferedColumnTable *) src;

            for(int i = 0; i < src_table->getSchema().getFieldCount(); ++i) {
                assert(src_table->getSchema().getField(i).size() == this->getSchema().getField(dst_col + i).size());
            }

            int write_idx = dst_col;
            for(int i = 0; i < src_table->getSchema().getFieldCount(); ++i) {
                // Get src unpacked page and pin it.
                Field<Bit> src_field = src_table->getField(src_row, i);

                int write_row_idx = dst_row;
                // Write n copies of src rows to dst rows
                // TODO: maybe we can optimize this by cloneColumn.
                for(int j = 0; j < copies; ++j) {
                    setField(write_row_idx, write_idx, src_field);
                    ++write_row_idx;
                }

                ++write_idx;
            }

            // Copy dummy tag
            Bit dummy_tag = src_table->getDummyTag(src_row);

            int write_dummy_row_idx = dst_row;
            for(int i = 0; i < copies; ++i) {
                setDummyTag(write_dummy_row_idx, dummy_tag);
                ++write_dummy_row_idx;
            }
        }

        void cloneColumn(const int & dst_col, const QueryTable<Bit> *src_table, const int &src_col) override {
            assert(src_table->getSchema().getField(src_col) == this->schema_.getField(dst_col));

            if(this->tuple_cnt_ == src_table->tuple_cnt_ && src_table->storageModel() == StorageModel::COLUMN_STORE) {
                BufferedColumnTable *src = (BufferedColumnTable *) src_table;
                this->conf_.bpm_.flushColumn(src->table_id_, src_col);

                // direct read/write from/to disk page by page
                for(int i = 0; i < src->pages_per_col[src_col]; ++i) {
                    PageId src_pid(src->table_id_, src_col, i);
                    PageId dst_pid(this->table_id_, dst_col, i);
                    this->conf_.bpm_.clonePage(src_pid, dst_pid);
                }

                return;
            }
            this->cloneColumn(dst_col, 0, src_table, src_col, 0);
        }

        void cloneColumn(const int & dst_col, const int & dst_row, const QueryTable<Bit> *src, const int & src_col, const int & src_row = 0) override {
            assert(src->getSchema().getField(src_col) == this->schema_.getField(dst_col));

            BufferedColumnTable *src_table = (BufferedColumnTable *) src;

            int rows_to_cp = src->tuple_cnt_ - src_row;
            if(rows_to_cp > this->tuple_cnt_ - dst_row) {
                rows_to_cp = this->tuple_cnt_ - dst_row;
            }

            int read_offset = src_row;
            int write_offset = dst_row;

            // this does not work 1:1 for copying whole wires
            // because we are pulling from arbitrary row offsets
            // and those row offsets might not align with page boundaries
            for(int i = 0; i < rows_to_cp; ++i) {
                Field<Bit> src_field = src_table->getField(read_offset, src_col);
                setField(write_offset, dst_col, src_field);
                ++read_offset;
                ++write_offset;
            }
        }

        StorageModel storageModel() const override { return StorageModel::COLUMN_STORE; }

        void deserializeRow(const int & row, vector<int8_t> & src) override {
            int src_size_bytes = src.size() - sizeof(emp::Bit); // don't handle dummy tag until end
            int cursor = 0; // bytes
            int write_idx = 0; // column indexes

            // does not include dummy tag - handle further down in this method
            // re-pack row
            while(cursor < src_size_bytes && write_idx < this->schema_.getFieldCount()) {
                int bytes_remaining = src_size_bytes - cursor;
                int dst_len = this->field_sizes_bytes_.at(write_idx);
                int to_read = (dst_len < bytes_remaining) ? dst_len : bytes_remaining;

                vector<int8_t> dst_arr(to_read);
                memcpy(dst_arr.data(), src.data() + cursor, to_read);
                Field<Bit> dst_field = Field<Bit>::deserialize(this->schema_.getField(write_idx), dst_arr.data());
                setField(row, write_idx, dst_field);

                cursor += to_read;
                ++write_idx;
            }

            emp::Bit *dummy_tag = (emp::Bit*) (src.data() + src.size() - sizeof(emp::Bit));
            setDummyTag(row, *dummy_tag);
        }

        std::vector<emp::Bit> readSecretSharedPageFromDisk(const PageId pid);

        std::vector<emp::Bit> readSecretSharedPageFromDisk(const PageId pid, const int tuple_cnt, const QuerySchema &schema, const int src_col, const string &src_data_path);

        std::vector<int8_t> convertEMPBitToWriteBuffer(const std::vector<emp::Bit> bits);

        void flushPage(const PageId &pid, emp::Bit *bits) override;

        ~BufferedColumnTable() {
            this->conf_.bpm_.removeTable(this->table_id_);
            if (std::filesystem::exists(this->file_path_)) {
                std::filesystem::remove_all(this->secret_shares_path_);

                if(std::filesystem::exists(this->file_path_) && std::filesystem::is_empty(this->file_path_)) {
                    //std::filesystem::remove_all(this->file_path_);
                }
            }
        }
    };
}

#endif

#endif
