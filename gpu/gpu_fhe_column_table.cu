#include "gpu_fhe_column_table.cuh"

namespace vaultdb {

void GpuFheColumnTable::addColumn(GpuFheColumn column) {
    const std::string& name = column.getName();
    if (name.empty())
        throw std::invalid_argument("GpuFheColumnTable::addColumn: column has no name");
    if (columns_.count(name))
        throw std::runtime_error("GpuFheColumnTable::addColumn: duplicate column '" + name + "'");

    if (row_count_ == 0 && !column.empty()) {
        row_count_ = column.getRowCount();
    }
    columns_.emplace(name, std::move(column));
}

bool GpuFheColumnTable::hasColumn(const std::string& name) const {
    return columns_.count(name) > 0;
}

GpuFheColumn& GpuFheColumnTable::getColumn(const std::string& name) {
    auto it = columns_.find(name);
    if (it == columns_.end())
        throw std::out_of_range("GpuFheColumnTable::getColumn: not found '" + name + "'");
    return it->second;
}

const GpuFheColumn& GpuFheColumnTable::getColumn(const std::string& name) const {
    auto it = columns_.find(name);
    if (it == columns_.end())
        throw std::out_of_range("GpuFheColumnTable::getColumn: not found '" + name + "'");
    return it->second;
}

std::vector<std::string> GpuFheColumnTable::getColumnNames() const {
    std::vector<std::string> names;
    names.reserve(columns_.size());
    for (const auto& [n, _] : columns_) {
        names.push_back(n);
    }
    return names;
}


} // namespace vaultdb
