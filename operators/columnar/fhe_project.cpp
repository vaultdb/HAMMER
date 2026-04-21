#include "operators/columnar/fhe_project.h"

#include <algorithm>
#include <stdexcept>
#include <unordered_map>

namespace vaultdb {

SortDefinition FheProject::remapSortDefinition(const SortDefinition& child_sort,
                                               const std::vector<int32_t>& projected_ordinals) {
    SortDefinition remapped;
    if (child_sort.empty()) return remapped;

    std::unordered_map<int, int> old_to_new;
    old_to_new.reserve(projected_ordinals.size());
    for (size_t i = 0; i < projected_ordinals.size(); ++i) {
        old_to_new[static_cast<int>(projected_ordinals[i])] = static_cast<int>(i);
    }

    for (const auto& s : child_sort) {
        if (s.first == -1) {
            remapped.push_back(s);
            continue;
        }
        auto it = old_to_new.find(s.first);
        if (it != old_to_new.end()) {
            remapped.emplace_back(it->second, s.second);
        }
    }
    return remapped;
}

FheProject::FheProject(ColumnOperator<void>* child,
                       const std::vector<int32_t>& projected_ordinals,
                       const std::vector<std::string>& output_aliases)
    : ColumnOperator<void>(SortDefinition{}, 0),
      projected_ordinals_(projected_ordinals),
      output_aliases_(output_aliases) {
    if (!child) {
        throw std::invalid_argument("FheProject: child operator is null");
    }
    if (projected_ordinals_.empty()) {
        throw std::invalid_argument("FheProject: projected ordinals cannot be empty");
    }
    if (!output_aliases_.empty() && output_aliases_.size() != projected_ordinals_.size()) {
        throw std::invalid_argument("FheProject: output_aliases size must match projected ordinals");
    }

    setChild(child, 0);
    output_cardinality_ = child->getOutputCardinality();
    sort_definition_ = remapSortDefinition(child->getSortOrder(), projected_ordinals_);

    QuerySchema child_schema = child->getOutputSchema();
    QuerySchema projected_schema;
    int new_ord = 0;
    for (size_t i = 0; i < projected_ordinals_.size(); ++i) {
        int src_ord = static_cast<int>(projected_ordinals_[i]);
        if (src_ord == -1) {
            if (!child_schema.hasField("dummy_tag")) {
                throw std::runtime_error("FheProject: projected ordinal -1 (dummy_tag) but child has no dummy_tag");
            }
            QueryFieldDesc fd = child_schema.getField("dummy_tag");
            projected_schema.putField(QueryFieldDesc(-1, "dummy_tag", fd.getTableName(), fd.getType(), 0));
            continue;
        }
        if (src_ord < 0 || src_ord >= child_schema.getFieldCount()) {
            throw std::runtime_error("FheProject: projected ordinal out of range: " + std::to_string(src_ord));
        }
        QueryFieldDesc fd = child_schema.getField(src_ord);
        fd.setOrdinal(new_ord++);
        if (!output_aliases_.empty() && !output_aliases_[i].empty()) {
            fd.setName(fd.getTableName(), output_aliases_[i]);
        }
        projected_schema.putField(fd);
    }
    if (child_schema.hasField("dummy_tag") &&
        std::find(projected_ordinals_.begin(), projected_ordinals_.end(), -1) == projected_ordinals_.end()) {
        QueryFieldDesc fd = child_schema.getField("dummy_tag");
        projected_schema.putField(QueryFieldDesc(-1, "dummy_tag", fd.getTableName(), fd.getType(), 0));
    }
    projected_schema.initializeFieldOffsets();
    output_schema_ = projected_schema;
}

std::shared_ptr<ColumnTableBase<void>> FheProject::runSelf() {
    if (!input_) {
        auto* child_op = getChild(0);
        if (!child_op) {
            throw std::runtime_error("FheProject: child operator is null");
        }
        auto child_result = child_op->runSelf();
        input_ = std::dynamic_pointer_cast<FheColumnTable>(child_result);
        if (!input_) {
            throw std::runtime_error("FheProject: child must return FheColumnTable");
        }
    }

    startTiming();

    const auto& input_schema = input_->getSchema();
    const size_t row_count = input_->getRowCount();

    auto projected_plain = std::make_shared<PlainColumnTable>(output_schema_, row_count);
    projected_plain->setFieldCount(static_cast<size_t>(output_schema_.getFieldCount()));
    projected_plain->setHasDummy(input_->getHasDummy());

    auto input_plain = input_->getPlainSnapshot();
    if (input_plain) {
        for (size_t i = 0; i < projected_ordinals_.size(); ++i) {
            int src_ord = static_cast<int>(projected_ordinals_[i]);
            std::string src_name;
            std::string out_name;
            if (src_ord == -1) {
                src_name = "dummy_tag";
                out_name = output_schema_.getField(-1).getName();
            } else {
                src_name = input_schema.getField(src_ord).getName();
                out_name = output_schema_.getField(static_cast<int>(i)).getName();
            }
            auto plain_col = input_plain->getPlainColumn(src_name);
            if (!plain_col) continue;
            projected_plain->addColumn(out_name, std::make_shared<PlainColumn>(*plain_col));
        }
    }

    auto projected = std::make_shared<FheColumnTable>(output_schema_, row_count);
    projected->setPlainTable(projected_plain);

    for (size_t i = 0; i < projected_ordinals_.size(); ++i) {
        int src_ord = static_cast<int>(projected_ordinals_[i]);
        std::string src_name;
        std::string out_name;
        if (src_ord == -1) {
            src_name = "dummy_tag";
            out_name = output_schema_.getField(-1).getName();
        } else {
            src_name = input_schema.getField(src_ord).getName();
            out_name = output_schema_.getField(static_cast<int>(i)).getName();
        }
        if (!input_->hasEncryptedColumn(src_name)) continue;

        auto src_col = input_->getFheColumn(src_name);
        if (!src_col) continue;

        // Reuse encrypted payload; rename only at schema/column metadata level if alias is provided.
        auto dst_col = std::make_shared<FheColumn>(out_name);
        for (const auto& chunk : src_col->getFheChunks()) {
            dst_col->addFheChunk(chunk);
        }
        projected->addColumn(dst_col);

        if (input_->getDummyTagColumn() && src_name == input_->getDummyTagColumn()->getName()) {
            projected->setDummyTagColumn(dst_col);
        }
    }

    if (output_schema_.hasField("dummy_tag") &&
        std::find(projected_ordinals_.begin(), projected_ordinals_.end(), -1) == projected_ordinals_.end()) {
        if (input_plain) {
            auto plain_dummy = input_plain->getPlainColumn("dummy_tag");
            if (plain_dummy) {
                projected_plain->addColumn("dummy_tag", std::make_shared<PlainColumn>(*plain_dummy));
            }
        }
        if (input_->hasEncryptedColumn("dummy_tag")) {
            auto src_col = input_->getFheColumn("dummy_tag");
            if (src_col) {
                auto dst_col = std::make_shared<FheColumn>("dummy_tag");
                for (const auto& chunk : src_col->getFheChunks()) {
                    dst_col->addFheChunk(chunk);
                }
                projected->addColumn(dst_col);
                if (input_->getDummyTagColumn() && input_->getDummyTagColumn()->getName() == "dummy_tag") {
                    projected->setDummyTagColumn(dst_col);
                }
            }
        }
    }

    projected->setFieldCount(static_cast<size_t>(output_schema_.getFieldCount()));
    projected->setHasDummy(input_->getHasDummy());
    output_ = projected;

    endTiming();
    printTiming();
    return output_;
}

std::string FheProject::getParameters() const {
    return "projected_cols=" + std::to_string(projected_ordinals_.size());
}

} // namespace vaultdb
