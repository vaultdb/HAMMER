#include "packed_column_table.h"
#include "computing_party_packed_column_table.h"
#include "input_party_packed_column_table.h"
#include "util/operator_utilities.h"

using namespace vaultdb;

#if  __has_include("emp-sh2pc/emp-sh2pc.h") || __has_include("emp-zk/emp-zk.h")
// do nothing
#else
// no ordinals, so read all cols, but only the first limit rows
PackedColumnTable *PackedColumnTable::deserialize(const TableMetadata  & md, const int & limit) {
    int src_tuple_cnt = md.tuple_cnt_;
    int tuple_cnt = (limit == -1 || limit > src_tuple_cnt) ? src_tuple_cnt : limit;

    if(SystemConfiguration::getInstance().inputParty()) {
        return new InputPartyPackedColumnTable(tuple_cnt, md.schema_, md.collation_);
    }


    string filename = Utilities::getFilenameForTable(md.name_);
    return new ComputingPartyPackedColumnTable(tuple_cnt, md.schema_, filename, md.tuple_cnt_, md.collation_);

}

PackedColumnTable *PackedColumnTable::deserialize(const TableMetadata  & md, const vector<int> & ordinals, const int & limit) {
    int src_tuple_cnt = md.tuple_cnt_;
    int tuple_cnt = (limit == -1 || limit > src_tuple_cnt) ? src_tuple_cnt : limit;

    // if no projection
    if(ordinals.empty()) {
       return deserialize(md, limit);
    }


    // else, first construct dst schema from projection
    auto dst_schema = OperatorUtilities::deriveSchema(md.schema_, ordinals);
    auto dst_collation = OperatorUtilities::deriveCollation(md.collation_, ordinals);

    if(SystemConfiguration::getInstance().inputParty()) {
        return new InputPartyPackedColumnTable(tuple_cnt, dst_schema, dst_collation);
    }

    // else
    // find the offsets to read in serialized file for each column
    map<int, long> src_ordinal_offsets = PackedColumnTable::getOrdinalOffsets(md.schema_, src_tuple_cnt);

    ComputingPartyPackedColumnTable *dst = (ComputingPartyPackedColumnTable *) QueryTable<Bit>::getTable(tuple_cnt, dst_schema, dst_collation);

    auto filename = Utilities::getFilenameForTable(md.name_);
    FILE*  fp = fopen(filename.c_str(), "rb");

    int dst_ordinal = 0;

    for(auto src_ordinal : ordinals) {
        fseek(fp,  src_ordinal_offsets[src_ordinal], SEEK_SET); // read read_offset bytes from beginning of file
        int col_size = bytesPerColumn(md.schema_.getField(src_ordinal), tuple_cnt);
        vector<int8_t> tmp = vector<int8_t>(col_size, 0);
        fread(tmp.data(), 1, col_size, fp);

        fseek(dst->packed_pages_file_, dst->ordinal_offsets_[dst_ordinal], SEEK_SET);
        fwrite(tmp.data(), 1, col_size, dst->packed_pages_file_);
        ++dst_ordinal;
    }

    // read dummy tag unconditionally
    fseek(fp, src_ordinal_offsets[-1], SEEK_SET);
    int read_size = bytesPerColumn(md.schema_.getField(-1), tuple_cnt);
    vector<int8_t> tmp = vector<int8_t>(read_size, 0);
    fread(tmp.data(), 1, read_size, fp);

    fseek(dst->packed_pages_file_, dst->ordinal_offsets_[-1], SEEK_SET);
    fwrite(tmp.data(), 1, tmp.size(), dst->packed_pages_file_);

    fflush(dst->packed_pages_file_);

    fclose(fp);
    return dst;

}

#endif
