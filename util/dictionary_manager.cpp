#include "util/dictionary_manager.h"

#include <boost/foreach.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <ctime>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace vaultdb {

namespace {

constexpr int kDefaultRadixBase = 8;
constexpr int kDefaultNumDigits = 4;

int64_t computeDaysFromEpoch(const std::string& date_str,
                             const std::string& epoch_start) {
  auto parse_date = [](const std::string& str) {
    std::tm t{};
    int y, m, d;
    if (std::sscanf(str.c_str(), "%d-%d-%d", &y, &m, &d) != 3) {
      throw std::runtime_error("Failed to parse date: " + str);
    }
    t.tm_year = y - 1900;
    t.tm_mon = m - 1;
    t.tm_mday = d;
    t.tm_hour = 0;
    t.tm_min = 0;
    t.tm_sec = 0;
    t.tm_isdst = -1;
    return static_cast<int64_t>(std::mktime(&t) / (24 * 3600));
  };
  return parse_date(date_str) - parse_date(epoch_start);
}

DictColumnType parseType(const std::string& s) {
  if (s == "date") return DictColumnType::DATE;
  if (s == "enum") return DictColumnType::ENUM;
  if (s == "integer") return DictColumnType::INTEGER;
  if (s == "decimal") return DictColumnType::DECIMAL;
  return DictColumnType::UNKNOWN;
}

}  // namespace

void DictionaryManager::load(const std::string& file_path) {
  file_path_ = file_path;
  std::ifstream f(file_path);
  if (!f.good()) {
    loaded_ = false;
    return;
  }
  std::stringstream ss;
  ss << f.rdbuf();
  f.close();

  boost::property_tree::ptree pt;
  try {
    boost::property_tree::read_json(ss, pt);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("DictionaryManager: failed to parse ") +
                             file_path + ": " + e.what());
  }

  version_.clear();
  columns_.clear();

  if (auto v = pt.get_child_optional("version")) {
    version_ = v->get_value<std::string>();
  }

  auto tables_opt = pt.get_child_optional("tables");
  if (!tables_opt) {
    loaded_ = true;
    return;
  }

  for (const auto& table_pair : *tables_opt) {
    const std::string& table_name = table_pair.first;
    const auto& table_pt = table_pair.second;

    for (const auto& col_pair : table_pt) {
      const std::string& col_name = col_pair.first;
      const auto& col_pt = col_pair.second;

      ColumnInfo info;
      if (auto t = col_pt.get_child_optional("type")) {
        info.type = parseType(t->get_value<std::string>());
      }
      if (auto s = col_pt.get_child_optional("strategy")) {
        if (auto rb = s->get_child_optional("radixBase")) {
          info.radix_base = rb->get_value<int>();
        }
        if (auto nd = s->get_child_optional("numDigits")) {
          info.num_digits = nd->get_value<int>();
        }
      }
      if (auto p = col_pt.get_child_optional("params")) {
        if (auto es = p->get_child_optional("epoch_start")) {
          info.epoch_start = es->get_value<std::string>();
        }
        if (auto sf = p->get_child_optional("scale_factor")) {
          info.scale_factor = sf->get_value<int>();
        }
      }
      if (auto m = col_pt.get_child_optional("mapping")) {
        if (!m->empty()) {
          for (const auto& kv : *m) {
            const std::string& key = kv.first;
            int val = kv.second.get_value<int>();
            info.mapping[key] = val;
          }
        }
      }

      columns_[table_name][col_name] = std::move(info);
    }
  }

  loaded_ = true;
}

int DictionaryManager::lookupId(const std::string& table,
                                const std::string& col,
                                const std::string& str_val) const {
  auto it_t = columns_.find(table);
  if (it_t == columns_.end()) {
    throw std::runtime_error("DictionaryManager: unknown table " + table);
  }
  auto it_c = it_t->second.find(col);
  if (it_c == it_t->second.end()) {
    throw std::runtime_error("DictionaryManager: unknown column " + table +
                             "." + col);
  }
  const auto& mapping = it_c->second.mapping;
  auto it_m = mapping.find(str_val);
  if (it_m == mapping.end()) {
    throw std::runtime_error("DictionaryManager: unknown value '" + str_val +
                             "' for " + table + "." + col);
  }
  return it_m->second;
}

std::string DictionaryManager::lookupString(const std::string& table,
                                            const std::string& col,
                                            int id) const {
  auto it_t = columns_.find(table);
  if (it_t == columns_.end()) return "";
  auto it_c = it_t->second.find(col);
  if (it_c == it_t->second.end()) return "";
  for (const auto& kv : it_c->second.mapping) {
    if (kv.second == id) return kv.first;
  }
  return "";
}

Strategy DictionaryManager::getStrategy(const std::string& table,
                                       const std::string& col) const {
  auto it_t = columns_.find(table);
  if (it_t == columns_.end()) {
    return {kDefaultRadixBase, kDefaultNumDigits};
  }
  auto it_c = it_t->second.find(col);
  if (it_c == it_t->second.end()) {
    return {kDefaultRadixBase, kDefaultNumDigits};
  }
  return {it_c->second.radix_base, it_c->second.num_digits};
}

int64_t DictionaryManager::dateToId(const std::string& table,
                                    const std::string& col,
                                    const std::string& date_str) const {
  auto it_t = columns_.find(table);
  if (it_t == columns_.end()) {
    throw std::runtime_error("DictionaryManager: unknown table " + table);
  }
  auto it_c = it_t->second.find(col);
  if (it_c == it_t->second.end()) {
    throw std::runtime_error("DictionaryManager: unknown column " + table +
                             "." + col);
  }
  const std::string& epoch = it_c->second.epoch_start;
  if (epoch.empty()) {
    throw std::runtime_error("DictionaryManager: no epoch_start for " + table +
                             "." + col);
  }
  return computeDaysFromEpoch(date_str, epoch);
}

DictColumnType DictionaryManager::getColumnType(const std::string& table,
                                                const std::string& col) const {
  auto it_t = columns_.find(table);
  if (it_t == columns_.end()) return DictColumnType::UNKNOWN;
  auto it_c = it_t->second.find(col);
  if (it_c == it_t->second.end()) return DictColumnType::UNKNOWN;
  return it_c->second.type;
}

int DictionaryManager::getScaleFactor(const std::string& table,
                                      const std::string& col) const {
  auto it_t = columns_.find(table);
  if (it_t == columns_.end()) return 1;
  auto it_c = it_t->second.find(col);
  if (it_c == it_t->second.end()) return 1;
  if (it_c->second.type != DictColumnType::DECIMAL) return 1;
  int scale = it_c->second.scale_factor;
  return scale > 0 ? scale : 100;
}

std::string DictionaryManager::getTableForColumn(const std::string& col) const {
  for (const auto& kv : columns_) {
    if (kv.second.count(col) > 0) {
      return kv.first;
    }
  }
  return "";
}

int64_t DictionaryManager::valueToInt64(const std::string& table,
                                        const std::string& col,
                                        const std::string& str_val) const {
  DictColumnType t = getColumnType(table, col);
  switch (t) {
    case DictColumnType::DATE:
      return dateToId(table, col, str_val);
    case DictColumnType::ENUM:
      return static_cast<int64_t>(lookupId(table, col, str_val));
    case DictColumnType::INTEGER: {
      try {
        return static_cast<int64_t>(std::stoll(str_val));
      } catch (const std::exception& e) {
        throw std::runtime_error("DictionaryManager: invalid integer '" +
                                 str_val + "' for " + table + "." + col);
      }
    }
    case DictColumnType::DECIMAL: {
      auto it_t = columns_.find(table);
      if (it_t == columns_.end() || it_t->second.count(col) == 0) {
        throw std::runtime_error("DictionaryManager: unknown column " + table +
                                 "." + col);
      }
      int scale = it_t->second.at(col).scale_factor;
      if (scale <= 0) scale = 100;
      try {
        double d = std::stod(str_val);
        return static_cast<int64_t>(d * scale + 0.5);
      } catch (const std::exception& e) {
        throw std::runtime_error("DictionaryManager: invalid decimal '" +
                                 str_val + "' for " + table + "." + col);
      }
    }
    default:
      throw std::runtime_error("DictionaryManager: unsupported type for " +
                               table + "." + col);
  }
}

int DictionaryManager::registerOrLookup(const std::string& table,
                                        const std::string& col,
                                        const std::string& str_val) {
  auto it_t = columns_.find(table);
  if (it_t == columns_.end()) {
    throw std::runtime_error("DictionaryManager: unknown table " + table);
  }
  auto it_c = it_t->second.find(col);
  if (it_c == it_t->second.end()) {
    throw std::runtime_error("DictionaryManager: unknown column " + table +
                             "." + col);
  }
  if (it_c->second.type != DictColumnType::ENUM) {
    throw std::runtime_error("DictionaryManager: registerOrLookup only for enum columns: " +
                             table + "." + col);
  }
  auto& mapping = it_c->second.mapping;
  auto it_m = mapping.find(str_val);
  if (it_m != mapping.end()) {
    return it_m->second;
  }
  int next_id = 0;
  for (const auto& kv : mapping) {
    if (kv.second >= next_id) next_id = kv.second + 1;
  }
  mapping[str_val] = next_id;
  // Dictionary is read-only; no save(). ETL with new values handled separately.
  return next_id;
}

void DictionaryManager::save() {
  if (file_path_.empty()) {
    throw std::runtime_error("DictionaryManager: cannot save, file path not set");
  }
  boost::property_tree::ptree pt;
  pt.put("version", version_.empty() ? "1.0" : version_);
  pt.put("description", "Optimized Dictionary Encoding for TPC-H FHE Execution");

  boost::property_tree::ptree tables_pt;
  for (const auto& table_pair : columns_) {
    const std::string& table_name = table_pair.first;
    boost::property_tree::ptree table_pt;
    for (const auto& col_pair : table_pair.second) {
      const std::string& col_name = col_pair.first;
      const ColumnInfo& info = col_pair.second;

      boost::property_tree::ptree col_pt;
      const char* type_str = "integer";
      switch (info.type) {
        case DictColumnType::DATE: type_str = "date"; break;
        case DictColumnType::ENUM: type_str = "enum"; break;
        case DictColumnType::INTEGER: type_str = "integer"; break;
        case DictColumnType::DECIMAL: type_str = "decimal"; break;
        default: break;
      }
      col_pt.put("type", type_str);
      boost::property_tree::ptree strat_pt;
      strat_pt.put("radixBase", info.radix_base);
      strat_pt.put("numDigits", info.num_digits);
      col_pt.add_child("strategy", strat_pt);

      if (!info.epoch_start.empty() || (info.type == DictColumnType::DECIMAL && info.scale_factor != 1)) {
        boost::property_tree::ptree params_pt;
        if (!info.epoch_start.empty()) params_pt.put("epoch_start", info.epoch_start);
        if (info.type == DictColumnType::DECIMAL && info.scale_factor != 1) {
          params_pt.put("scale_factor", info.scale_factor);
        }
        col_pt.add_child("params", params_pt);
      }
      if (!info.mapping.empty()) {
        boost::property_tree::ptree map_pt;
        for (const auto& kv : info.mapping) {
          map_pt.put(kv.first, std::to_string(kv.second));
        }
        col_pt.add_child("mapping", map_pt);
      }
      table_pt.add_child(col_name, col_pt);
    }
    tables_pt.add_child(table_name, table_pt);
  }
  pt.add_child("tables", tables_pt);

  try {
    boost::property_tree::write_json(file_path_, pt, std::locale(), true);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("DictionaryManager: failed to save ") +
                             file_path_ + ": " + e.what());
  }
}

}  // namespace vaultdb
