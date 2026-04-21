#include "operators/columnar/secure_context_switch.h"
#include <util/system_configuration.h>
#include <util/fhe/fhe_to_mpc_decrypt.h>
#include <util/fhe/column_to_row_encoder.h>
#include <util/fhe/fhe_helpers.h>
#include <query_table/columnar/column_table_base.h>
#include <query_table/column_table.h>
#include <query_table/field/field.h>
#include <query_table/field/field_type.h>
#include <operators/sort.h>
#include <parser/plan_parser.h>
#include <util/fhe/fhe_mpc_party_b.h>
#include <util/fhe/fhe_mpc_party_c.h>
#include <gflags/gflags.h>
#include <chrono>
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>

DECLARE_string(fhe_bob_host);
DECLARE_int32(sort_limit);

// FHE->MPC security: (1) Correct order is "add then modulo": Reveal(Secure_Sum) then reduce mod
// P_TOTAL. (2) B and C must run the SAME protocol (secretShareAdditive) so that the revealed
// value is M = R + (M-R). If each party revealed locally with the other input as 0, they would
// see only R or only (M-R), not M. (3) After reveal, use ReduceModPTotal() for aggregate columns
// when the result can exceed P_TOTAL_3PRIME (see fhe_helpers.h).

namespace vaultdb {
namespace {

void ApplySecureDummyTagsFromRowMarker(SecureTable* secure_table) {
    if (!secure_table) return;
    const QuerySchema& schema = secure_table->getSchema();
    // FHE->MPC: dummy is sent as temp column _row_marker (LONG). B+C reveal M; if M==0 set dummy_tag true, else false.
    if (!schema.hasField("_row_marker")) return;

    int marker_col_idx = schema.getField("_row_marker").getOrdinal();
    const auto& marker_fd = schema.getField(marker_col_idx);
    int bit_len = static_cast<int>(marker_fd.size()) + (marker_fd.bitPacked() ? 1 : 0);
    if (bit_len <= 0) bit_len = 64;
    emp::Integer zero_marker(bit_len, 0, emp::PUBLIC);

    for (size_t r = 0; r < secure_table->tuple_cnt_; ++r) {
        Field<emp::Bit> marker_field = secure_table->getField(static_cast<int>(r), marker_col_idx);
        emp::Integer marker_val = marker_field.getInt().resize(bit_len);
        emp::Bit is_dummy = (marker_val == zero_marker);
        secure_table->setDummyTag(static_cast<int>(r), is_dummy);
    }
}

/// Reduce encrypted columns in-circuit to [0, P_TOTAL_3PRIME) so that (R + (M-R)) wraps correctly.
/// Both Party B and Party C must execute the identical circuit for MPC consistency.
void CanonicalizeEncryptedColumns(SecureTable* table, const std::vector<int>& col_indices) {
    const auto& schema = table->getSchema();
    for (int col_idx : col_indices) {
        const auto& fd = schema.getField(col_idx);
        if (fd.getType() != FieldType::SECURE_LONG && fd.getType() != FieldType::SECURE_INT) continue;
        int bit_len = static_cast<int>(fd.size()) + (fd.bitPacked() ? 1 : 0);
        if (bit_len <= 0) bit_len = 64;
        emp::Integer mod_int(bit_len, static_cast<int64_t>(P_TOTAL_3PRIME), emp::PUBLIC);
        Field<emp::Bit> mod_field(fd.getType(), mod_int);
        for (size_t r = 0; r < table->tuple_cnt_; ++r) {
            auto cur = table->getField(static_cast<int>(r), col_idx);
            auto reduced = cur % mod_field;
            table->setField(static_cast<int>(r), col_idx, reduced);
        }
    }
}

/// Remove temp column _row_marker from the MPC table after dummy_tag has been set from it.
/// Full table copy is needed because SecureTable doesn't support lazy column removal.
void DropRowMarkerColumn(SecureTable*& secure_table) {
    if (!secure_table || !secure_table->getSchema().hasField("_row_marker")) return;
    const QuerySchema& old_schema = secure_table->getSchema();
    const int row_marker_ordinal = old_schema.getField("_row_marker").getOrdinal();

    QuerySchema new_schema;
    for (int i = 0; i < old_schema.getFieldCount(); ++i) {
        if (i != row_marker_ordinal)
            new_schema.putField(old_schema.getField(i));
    }
    if (old_schema.hasField("dummy_tag"))
        new_schema.putField(old_schema.getField(-1));
    new_schema.initializeFieldOffsets();

    SecureTable* new_table = QueryTable<emp::Bit>::getTable(
        secure_table->tuple_cnt_, new_schema, secure_table->order_by_);
    for (size_t r = 0; r < secure_table->tuple_cnt_; ++r) {
        for (int col = 0; col < new_schema.getFieldCount(); ++col)
            new_table->setField(static_cast<int>(r), col,
                secure_table->getField(static_cast<int>(r), col));
        new_table->setDummyTag(static_cast<int>(r), secure_table->getDummyTag(static_cast<int>(r)));
    }
    delete secure_table;
    secure_table = new_table;
}

}  // namespace

QuerySchema SecureContextSwitch::BuildSafeSchema(const QuerySchema& schema) {
    QuerySchema safe;
    for (int i = 0; i < schema.getFieldCount(); ++i) {
        const auto& f = schema.getField(i);
        if (f.getType() == FieldType::STRING) {
            QueryFieldDesc d(f.getOrdinal(), f.getName(), f.getTableName(), FieldType::LONG, f.getStringLength());
            safe.putField(d);
        } else if (f.getType() == FieldType::INT) {
            QueryFieldDesc d(f.getOrdinal(), f.getName(), f.getTableName(), FieldType::LONG, 0);
            safe.putField(d);
        } else {
            safe.putField(f);
        }
    }
    safe.initializeFieldOffsets();
    return safe;
}

SecureContextSwitch::SecureContextSwitch(Operator<void>* fhe_child,
                                         int mpc_port,
                                         const std::string& charlie_host,
                                         bool decryption_in_mpc,
                                         int mpc_in_circuit_port)
    : Operator<emp::Bit>(SortDefinition{}),
      fhe_child_(fhe_child),
      secure_table_(nullptr),
      mpc_port_(mpc_port),
      charlie_host_(charlie_host),
      decryption_in_mpc_(decryption_in_mpc),
      mpc_in_circuit_port_(mpc_in_circuit_port),
      mpc_mgr_temp_(nullptr) {
    if (!fhe_child_)
        throw std::invalid_argument("SecureContextSwitch: fhe_child is null");
    auto* col = reinterpret_cast<ColumnOperator<void>*>(fhe_child_);
    output_schema_ = BuildSafeSchema(col->getOutputSchema());
    output_cardinality_ = col->getOutputCardinality();
    // Preserve child collation (e.g., group-by key order 0,1) until LogicalSort runs.
    sort_definition_ = col->getSortOrder();
}

SecureContextSwitch::SecureContextSwitch(std::shared_ptr<FheColumnTable> input_table,
                                         int mpc_port,
                                         const std::string& charlie_host,
                                         bool decryption_in_mpc,
                                         int mpc_in_circuit_port)
    : Operator<emp::Bit>(SortDefinition{}),
      input_table_(input_table),
      secure_table_(nullptr),
      mpc_port_(mpc_port),
      charlie_host_(charlie_host),
      decryption_in_mpc_(decryption_in_mpc),
      mpc_in_circuit_port_(mpc_in_circuit_port),
      mpc_mgr_temp_(nullptr) {
    if (!input_table_)
        throw std::invalid_argument("SecureContextSwitch: input_table is null");
    output_schema_ = BuildSafeSchema(input_table_->getSchema());
    output_cardinality_ = input_table_->getRowCount();
}

SecureContextSwitch::SecureContextSwitch(int mpc_port,
                                         const std::string& charlie_host,
                                         bool decryption_in_mpc,
                                         int mpc_in_circuit_port)
    : Operator<emp::Bit>(SortDefinition{}),
      secure_table_(nullptr),
      mpc_port_(mpc_port),
      charlie_host_(charlie_host),
      decryption_in_mpc_(decryption_in_mpc),
      mpc_in_circuit_port_(mpc_in_circuit_port),
      mpc_mgr_temp_(nullptr) {}

SecureContextSwitch::~SecureContextSwitch() {
    // output_ (secure_table_) owned by Operator base; do not delete
    secure_table_ = nullptr;
}

void SecureContextSwitch::setSortDefinition(const SortDefinition& sd) {
    sort_def_ = sd;
    // Keep existing child collation in sort_definition_.
    // sd is forwarded to Party C and used by parent LogicalSort only.
}

QueryTable<emp::Bit>* SecureContextSwitch::runSelf() {
    SystemConfiguration& sys_config = SystemConfiguration::getInstance();
    int party = sys_config.party_;

    if (party == 2) {
        std::cout << "[SecureContextSwitch] Party B: Starting FHE -> MPC transition..." << std::endl;

        if (!input_table_) {
            if (!fhe_child_)
                throw std::runtime_error("SecureContextSwitch: fhe_child is null");
            auto* col = reinterpret_cast<ColumnOperator<void>*>(fhe_child_);
            auto result = col->runSelf();
            input_table_ = std::dynamic_pointer_cast<FheColumnTable>(result);
            if (!input_table_)
                throw std::runtime_error("SecureContextSwitch: child must return FheColumnTable");
        }

        // Start timing only for SCS own work (exclude child FHE pipeline runtime)
        this->start_time_ = clock_start();
        this->start_gate_cnt_ = this->system_conf_.andGateCount();

        std::cout << "[SecureContextSwitch] Party B: Connecting to Party C at " << charlie_host_ << ":" << mpc_port_ << std::endl;
        const int kMaxRetries = 40;
        const int kRetryMs = 500;
        for (int attempt = 1; attempt <= kMaxRetries; ++attempt) {
            try {
                mpc_network_io_ = std::make_unique<FheNetworkIO>(charlie_host_, mpc_port_, false);
                break;
            } catch (const std::exception& e) {
                if (attempt == kMaxRetries) throw;
                std::cout << "[SecureContextSwitch] Party B: " << e.what() << " — retry " << attempt << "/" << kMaxRetries << " in " << kRetryMs << " ms" << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(kRetryMs));
            }
        }
        std::cout << "[SecureContextSwitch] Party B: Connected to Party C" << std::endl;

        const QuerySchema& original_schema = input_table_->getSchema();
        QuerySchema safe_schema = BuildSafeSchema(original_schema);
        display_schema_for_party_a_ = safe_schema;
        display_schema_set_ = true;
        size_t row_count = input_table_->getRowCount();
        if (FLAGS_sort_limit > 0 && static_cast<size_t>(FLAGS_sort_limit) < row_count) {
            std::cout << "[SecureContextSwitch] sort_limit=" << FLAGS_sort_limit
                      << " capping rows from " << row_count << std::endl;
            row_count = static_cast<size_t>(FLAGS_sort_limit);
        }
        int field_count = static_cast<int>(safe_schema.getFieldCount());

        auto original_snapshot = input_table_->getPlainSnapshot();
        if (!original_snapshot) {
            throw std::runtime_error("SecureContextSwitch Party B: missing plain snapshot");
        }
        // Step 3: Normalize all non-integer scalar types to LONG so MPC sort/sharing uses Integer only.
        QuerySchema mpc_schema;
        for (int i = 0; i < safe_schema.getFieldCount(); ++i) {
            const auto& fd = safe_schema.getField(i);
            if (fd.getType() == FieldType::FLOAT || fd.getType() == FieldType::DATE || fd.getType() == FieldType::BOOL) {
                mpc_schema.putField(QueryFieldDesc(fd.getOrdinal(), fd.getName(), fd.getTableName(), FieldType::LONG, fd.getStringLength()));
            } else {
                mpc_schema.putField(fd);
            }
        }
        // FHE dummy_tag -> MPC temp column _row_marker (LONG); ApplySecureDummyTagsFromRowMarker sets row-level dummy from it.
        const int row_marker_ordinal = safe_schema.getFieldCount();
        if (original_schema.hasField("dummy_tag") && input_table_->hasEncryptedColumn("dummy_tag")) {
            mpc_schema.putField(QueryFieldDesc(row_marker_ordinal, "_row_marker", "", FieldType::LONG, 0));
        }
        mpc_schema.initializeFieldOffsets();

        // encrypted_col_indices: FHE column indices to decrypt (may include -1 for dummy_tag).
        // encrypted_mpc_ordinals: MPC ordinals where to put decrypted values (use _row_marker ordinal instead of -1).
        std::vector<int> encrypted_col_indices;
        std::vector<int> plain_col_indices;
        encrypted_col_indices.reserve(static_cast<size_t>(field_count) + 1u);
        plain_col_indices.reserve(static_cast<size_t>(field_count));
        for (int col_idx = 0; col_idx < field_count; ++col_idx) {
            const std::string& col_name = original_schema.getField(col_idx).getName();
            if (input_table_->hasEncryptedColumn(col_name)) encrypted_col_indices.push_back(col_idx);
            else plain_col_indices.push_back(col_idx);
        }
        if (original_schema.hasField("dummy_tag") && input_table_->hasEncryptedColumn("dummy_tag")) {
            encrypted_col_indices.push_back(-1);
        }
        std::vector<int> encrypted_mpc_ordinals;
        for (int idx : encrypted_col_indices) {
            encrypted_mpc_ordinals.push_back(idx == -1 ? row_marker_ordinal : idx);
        }

        int field_count_send = mpc_schema.getFieldCount() + (mpc_schema.fieldInitialized(-1) ? 1 : 0);
        mpc_network_io_->sendData(&row_count, sizeof(size_t));
        mpc_network_io_->sendData(&field_count_send, sizeof(int));
        for (int col_idx = 0; col_idx < mpc_schema.getFieldCount(); ++col_idx) {
            const auto& field_desc = mpc_schema.getField(col_idx);
            std::string field_name = field_desc.getName();
            size_t name_len = field_name.size();
            mpc_network_io_->sendData(&name_len, sizeof(size_t));
            mpc_network_io_->sendData(field_name.data(), name_len);
            int ft = static_cast<int>(field_desc.getType());
            mpc_network_io_->sendData(&ft, sizeof(int));
            int ord = field_desc.getOrdinal();
            mpc_network_io_->sendData(&ord, sizeof(int));
            size_t slen = field_desc.getStringLength();
            mpc_network_io_->sendData(&slen, sizeof(size_t));
        }
        if (mpc_schema.fieldInitialized(-1)) {
            const auto& dummy_fd = mpc_schema.getField("dummy_tag");
            std::string field_name = dummy_fd.getName();
            size_t name_len = field_name.size();
            mpc_network_io_->sendData(&name_len, sizeof(size_t));
            mpc_network_io_->sendData(field_name.data(), name_len);
            int ft = static_cast<int>(dummy_fd.getType());
            mpc_network_io_->sendData(&ft, sizeof(int));
            int ord = dummy_fd.getOrdinal();
            mpc_network_io_->sendData(&ord, sizeof(int));
            size_t slen = static_cast<size_t>(dummy_fd.getStringLength());
            mpc_network_io_->sendData(&slen, sizeof(size_t));
        }
        int sort_count = static_cast<int>(sort_def_.size());
        mpc_network_io_->sendData(&sort_count, sizeof(int));
        for (const auto& cs : sort_def_) {
            int field_idx = cs.first;
            int dir = (cs.second == SortDirection::ASCENDING) ? 0 : 1;
            mpc_network_io_->sendData(&field_idx, sizeof(int));
            mpc_network_io_->sendData(&dir, sizeof(int));
        }
        mpc_network_io_->sendData(&limit_, sizeof(int));
        int encrypted_col_count = static_cast<int>(encrypted_mpc_ordinals.size());
        mpc_network_io_->sendData(&encrypted_col_count, sizeof(int));
        for (int idx : encrypted_mpc_ordinals) {
            mpc_network_io_->sendData(&idx, sizeof(int));
        }
        std::cout << "[SecureContextSwitch] Party B: Schema and sort info sent to Party C" << std::endl;

        const auto& cc = PlanParser<void>::getPartyACryptoContext();
        const auto& pk = PlanParser<void>::getPartyAPublicKey();
        const auto& sk_share = PlanParser<void>::getPartySecretKeyShare();

        std::vector<std::vector<int64_t>> r_values_per_column = RunMpcPartyB(
            mpc_network_io_.get(), input_table_, cc, pk, sk_share,
            encrypted_col_indices,
            decryption_in_mpc_, false, nullptr, mpc_in_circuit_port_);
        std::cout << "[SecureContextSwitch] Party B: Received " << r_values_per_column.size() << " encrypted columns (R)" << std::endl;

        auto safe_snapshot = std::make_shared<PlainColumnTable>(mpc_schema, row_count);
        for (int col_idx : plain_col_indices) {
            const auto& safe_fd = mpc_schema.getField(col_idx);
            const std::string& col_name = safe_fd.getName();
            auto orig_col = original_snapshot->getPlainColumn(col_name);
            if (!orig_col)
                throw std::runtime_error("SecureContextSwitch Party B: missing column " + col_name);
            std::vector<PlainField> new_fields;
            new_fields.reserve(row_count);
            const auto& orig_fd = original_schema.getField(col_idx);
            size_t copied = 0;
            for (const auto& chunk : orig_col->getPlainChunks()) {
                for (const PlainField& val : chunk->getValues()) {
                    if (copied >= row_count) break;
                    int64_t long_val = 0;
                    if (orig_fd.getType() == FieldType::STRING) {
                        std::string s = val.getString();
                        if (!s.empty()) long_val = static_cast<int64_t>(static_cast<unsigned char>(s[0]));
                    } else if (orig_fd.getType() == FieldType::INT) {
                        long_val = static_cast<int64_t>(val.getValue<int32_t>());
                    } else if (orig_fd.getType() == FieldType::BOOL) {
                        long_val = val.getValue<bool>() ? 1 : 0;
                    } else if (orig_fd.getType() == FieldType::FLOAT) {
                        // Scaled integer (10^6) for MPC sort; no float in circuit.
                        long_val = static_cast<int64_t>(std::round(val.getValue<float>() * 1000000.0));
                    } else if (orig_fd.getType() == FieldType::DATE) {
                        if (val.getType() == FieldType::INT) long_val = static_cast<int64_t>(val.getValue<int32_t>());
                        else long_val = val.getValue<int64_t>();
                    } else {
                        long_val = val.getValue<int64_t>();
                    }
                    new_fields.emplace_back(FieldType::LONG, long_val);
                    ++copied;
                }
                if (copied >= row_count) break;
            }
            if (copied < row_count) {
                throw std::runtime_error("SecureContextSwitch Party B: plain column shorter than row_count for " + col_name);
            }
            auto plain_chunk = std::make_shared<PlainColumnChunk>(new_fields);
            auto plain_col = std::make_shared<PlainColumn>(col_name);
            plain_col->addChunk(plain_chunk);
            safe_snapshot->addColumn(col_name, plain_col);
        }

        std::unique_ptr<PlainTable> plain_table(
            SecretShareToPlainTable(mpc_schema, safe_snapshot, r_values_per_column, encrypted_mpc_ordinals));
        std::cout << "[SecureContextSwitch] Party B: PlainTable created, initializing MPC..." << std::endl;

        if (!sys_config.hasMpc()) {
            int mpc_share_port = mpc_port_ + 1;
            std::cout << "[SecureContextSwitch] Party B: EMP ALICE connecting to " << charlie_host_ << ":" << mpc_share_port << " (reverse_connect)" << std::endl;
            mpc_mgr_temp_ = new SH2PCManager(charlie_host_, emp::ALICE, mpc_share_port, true);
            sys_config.setMpc(mpc_mgr_temp_);
        }
        auto orig_mode = sys_config.crypto_mode_;
        auto orig_mgr = sys_config.crypto_manager_;
        sys_config.crypto_mode_ = CryptoMode::EMP_SH2PC;
        sys_config.crypto_manager_ = sys_config.mpc();

        secure_table_ = plain_table->secretShareAdditive(emp::ALICE);
        CanonicalizeEncryptedColumns(secure_table_, encrypted_mpc_ordinals);
        ApplySecureDummyTagsFromRowMarker(secure_table_);
        DropRowMarkerColumn(secure_table_);
        std::cout << "[SecureContextSwitch] Party B: SecureTable created, rows=" << secure_table_->tuple_cnt_ << std::endl;
        std::cout << "[Step 5] Party B: Val_B=R input; MPC Secure_Sum=Share(Val_C)+Share(Val_B); Reveal -> M" << std::endl;

        sys_config.crypto_mode_ = orig_mode;
        sys_config.crypto_manager_ = orig_mgr;
    }
    else if (party == 3) {
        std::cout << "[SecureContextSwitch] Party C: Starting FHE -> MPC transition..." << std::endl;
        this->start_time_ = clock_start();
        this->start_gate_cnt_ = this->system_conf_.andGateCount();
        std::cout << "[SecureContextSwitch] Party C: Listening on 0.0.0.0:" << mpc_port_ << " for Party B" << std::endl;
        mpc_network_io_ = std::make_unique<FheNetworkIO>("0.0.0.0", mpc_port_, true);
        std::cout << "[SecureContextSwitch] Party C: Party B connected" << std::endl;

        size_t row_count = 0;
        mpc_network_io_->recvData(&row_count, sizeof(size_t));
        if (row_count == std::numeric_limits<size_t>::max()) {
            std::cout << "[SecureContextSwitch] Party C: Received no-MPC termination signal from Party B. Exiting handover." << std::endl;
            secure_table_ = nullptr;
            return nullptr;
        }
        int field_count = 0;
        mpc_network_io_->recvData(&field_count, sizeof(int));

        QuerySchema reconstructed_schema;
        for (int col_idx = 0; col_idx < field_count; ++col_idx) {
            size_t name_len = 0;
            mpc_network_io_->recvData(&name_len, sizeof(size_t));
            std::string field_name(name_len, '\0');
            mpc_network_io_->recvData(&field_name[0], name_len);
            int ft_int = 0;
            mpc_network_io_->recvData(&ft_int, sizeof(int));
            FieldType ft = static_cast<FieldType>(ft_int);
            int ord = 0;
            mpc_network_io_->recvData(&ord, sizeof(int));
            size_t slen = 0;
            mpc_network_io_->recvData(&slen, sizeof(size_t));
            QueryFieldDesc fd(ord, field_name, "mpc_transfer", ft, static_cast<int>(slen));
            reconstructed_schema.putField(fd);
        }
        reconstructed_schema.initializeFieldOffsets();

        int sort_count = 0;
        mpc_network_io_->recvData(&sort_count, sizeof(int));
        sort_def_.clear();
        sort_def_.reserve(static_cast<size_t>(std::max(0, sort_count)));
        for (int i = 0; i < sort_count; ++i) {
            int field_idx = 0, dir = 0;
            mpc_network_io_->recvData(&field_idx, sizeof(int));
            mpc_network_io_->recvData(&dir, sizeof(int));
            sort_def_.emplace_back(field_idx, dir == 0 ? SortDirection::ASCENDING : SortDirection::DESCENDING);
        }
        mpc_network_io_->recvData(&limit_, sizeof(int));
        int encrypted_col_count = 0;
        mpc_network_io_->recvData(&encrypted_col_count, sizeof(int));
        if (encrypted_col_count < 0 || encrypted_col_count > field_count) {
            throw std::runtime_error("SecureContextSwitch Party C: invalid encrypted column count");
        }
        std::vector<int> encrypted_col_indices;
        encrypted_col_indices.reserve(static_cast<size_t>(encrypted_col_count));
        for (int i = 0; i < encrypted_col_count; ++i) {
            int idx = -1;
            mpc_network_io_->recvData(&idx, sizeof(int));
            if (idx != -1 && (idx < 0 || idx >= field_count)) {
                throw std::runtime_error("SecureContextSwitch Party C: invalid encrypted column index");
            }
            encrypted_col_indices.push_back(idx);
        }

        QuerySchema safe_schema = BuildSafeSchema(reconstructed_schema);
        if (reconstructed_schema.fieldInitialized(-1)) {
            safe_schema.putField(QueryFieldDesc(-1, "dummy_tag", "", FieldType::LONG, 0));
            safe_schema.initializeFieldOffsets();
        }
        const auto& cc = PlanParser<void>::getPartyACryptoContext();
        const auto& pk = PlanParser<void>::getPartyAPublicKey();
        const auto& sk_share = PlanParser<void>::getPartySecretKeyShare();

        std::vector<std::vector<int64_t>> m_minus_r_per_column = RunMpcPartyC(
            mpc_network_io_.get(), cc, pk, sk_share, decryption_in_mpc_);
        const int num_agg_cols = static_cast<int>(m_minus_r_per_column.size());
        std::cout << "[SecureContextSwitch] Party C: Received " << num_agg_cols << " encrypted columns (M-R)" << std::endl;
        if (num_agg_cols != encrypted_col_count) {
            throw std::runtime_error("SecureContextSwitch Party C: encrypted column count mismatch");
        }

        auto plain_snapshot = std::make_shared<PlainColumnTable>(safe_schema, row_count);
        std::vector<bool> is_encrypted(static_cast<size_t>(safe_schema.getFieldCount()), false);
        for (int idx : encrypted_col_indices) {
            if (idx >= 0 && static_cast<size_t>(idx) < is_encrypted.size()) is_encrypted[static_cast<size_t>(idx)] = true;
        }
        for (int col_idx = 0; col_idx < safe_schema.getFieldCount(); ++col_idx) {
            if (is_encrypted[static_cast<size_t>(col_idx)]) continue;
            const auto& fd = safe_schema.getField(col_idx);
            std::vector<PlainField> fv;
            fv.reserve(row_count);
            for (size_t r = 0; r < row_count; ++r)
                fv.emplace_back(FieldType::LONG, static_cast<int64_t>(0));
            auto chunk = std::make_shared<PlainColumnChunk>(fv);
            auto plain_col = std::make_shared<PlainColumn>(fd.getName());
            plain_col->addChunk(chunk);
            plain_snapshot->addColumn(fd.getName(), plain_col);
        }

        std::unique_ptr<PlainTable> plain_table(
            SecretShareToPlainTable(safe_schema, plain_snapshot, m_minus_r_per_column, encrypted_col_indices));
        std::cout << "[SecureContextSwitch] Party C: PlainTable created, initializing MPC..." << std::endl;

        if (!sys_config.hasMpc()) {
            int mpc_share_port = mpc_port_ + 1;
            std::cout << "[SecureContextSwitch] Party C: EMP BOB listening on 0.0.0.0:" << mpc_share_port << " (reverse_connect)" << std::endl;
            mpc_mgr_temp_ = new SH2PCManager("", emp::BOB, mpc_share_port, true);
            sys_config.setMpc(mpc_mgr_temp_);
        }
        auto orig_mode = sys_config.crypto_mode_;
        auto orig_mgr = sys_config.crypto_manager_;
        sys_config.crypto_mode_ = CryptoMode::EMP_SH2PC;
        sys_config.crypto_manager_ = sys_config.mpc();

        secure_table_ = plain_table->secretShareAdditive(emp::BOB);
        CanonicalizeEncryptedColumns(secure_table_, encrypted_col_indices);
        ApplySecureDummyTagsFromRowMarker(secure_table_);
        DropRowMarkerColumn(secure_table_);
        std::cout << "[SecureContextSwitch] Party C: SecureTable created, rows=" << secure_table_->tuple_cnt_ << std::endl;
        std::cout << "[Step 5] Party C: Val_C=(M-R) input; MPC Secure_Sum=Share(Val_C)+Share(Val_B); Reveal -> M" << std::endl;

        sys_config.crypto_mode_ = orig_mode;
        sys_config.crypto_manager_ = orig_mgr;
    }
    else if (party == 1) {
        this->start_time_ = clock_start();
        this->start_gate_cnt_ = this->system_conf_.andGateCount();
        std::cout << "[SecureContextSwitch] Party A: No handover needed (reveal only)" << std::endl;
        return nullptr;
    }
    else {
        throw std::runtime_error("SecureContextSwitch: Invalid party: " + std::to_string(party));
    }

    return secure_table_;
}

Operator<emp::Bit>* SecureContextSwitch::clone() const {
    if (fhe_child_) {
        auto* c = new SecureContextSwitch(fhe_child_, mpc_port_, charlie_host_, decryption_in_mpc_, mpc_in_circuit_port_);
        c->sort_def_ = sort_def_;
        c->limit_ = limit_;
        c->sort_definition_ = sort_definition_;
        c->output_schema_ = output_schema_;
        c->output_cardinality_ = output_cardinality_;
        return c;
    }
    if (input_table_) {
        auto* c = new SecureContextSwitch(input_table_, mpc_port_, charlie_host_, decryption_in_mpc_, mpc_in_circuit_port_);
        c->sort_def_ = sort_def_;
        c->limit_ = limit_;
        c->sort_definition_ = sort_definition_;
        return c;
    }
    auto* c = new SecureContextSwitch(mpc_port_, charlie_host_, decryption_in_mpc_, mpc_in_circuit_port_);
    c->sort_def_ = sort_def_;
    c->limit_ = limit_;
    c->sort_definition_ = sort_definition_;
    return c;
}

bool SecureContextSwitch::operator==(const Operator<emp::Bit>& other) const {
    if (other.getType() != OperatorType::SECURE_CONTEXT_SWITCH) return false;
    auto* o = dynamic_cast<const SecureContextSwitch*>(&other);
    if (!o) return false;
    return fhe_child_ == o->fhe_child_ && mpc_port_ == o->mpc_port_ && charlie_host_ == o->charlie_host_;
}

std::string SecureContextSwitch::getParameters() const {
    return "SecureContextSwitch(mpc_port=" + std::to_string(mpc_port_) + ", charlie_host=" + charlie_host_ + ")";
}

}  // namespace vaultdb
