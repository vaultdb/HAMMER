#ifndef VAULTDB_DICTIONARY_MANAGER_H_
#define VAULTDB_DICTIONARY_MANAGER_H_

#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace vaultdb {

/// Column value type in the metadata dictionary.
enum class DictColumnType { DATE, ENUM, INTEGER, DECIMAL, UNKNOWN };

/// Strategy for FHE radix encoding: (radix_base, num_digits).
using Strategy = std::pair<int, int>;

/// Manages the metadata dictionary for FHE predicate encoding.
/// Used by both ETL (server) and query (client) to map values and get strategies.
class DictionaryManager {
 public:
  static DictionaryManager& getInstance() {
    static DictionaryManager instance;
    return instance;
  }

  DictionaryManager(const DictionaryManager&) = delete;
  DictionaryManager& operator=(const DictionaryManager&) = delete;

  /// Load dictionary from JSON file. No-op if file does not exist.
  /// \param file_path Path to metadata_dictionary.json (e.g. conf/plans/fhe/tpch_metadata_dictionary.json)
  void load(const std::string& file_path);

  /// Whether the dictionary has been loaded and contains data.
  bool isLoaded() const { return loaded_; }

  /// Dictionary version string (from JSON "version" field). Empty if not loaded.
  const std::string& getVersion() const { return version_; }

  /// Look up string value to integer ID (for enum columns).
  /// \throws std::runtime_error if table/column unknown or value not in mapping
  int lookupId(const std::string& table, const std::string& col,
               const std::string& str_val) const;

  /// Reverse lookup: integer ID to string (for enum columns, e.g. display).
  /// \returns empty string if table/column unknown or id not in mapping
  std::string lookupString(const std::string& table, const std::string& col,
                           int id) const;

  /// Get FHE encoding strategy (radix_base, num_digits) for a column.
  /// Returns default (8, 4) if column not found.
  Strategy getStrategy(const std::string& table, const std::string& col) const;

  /// Convert date string to relative days from epoch (for date columns).
  /// Uses params.epoch_start from the column config.
  /// \throws std::runtime_error if table/column unknown or date parse fails
  int64_t dateToId(const std::string& table, const std::string& col,
                   const std::string& date_str) const;

  /// Get column type from dictionary. Returns UNKNOWN if not found.
  DictColumnType getColumnType(const std::string& table,
                               const std::string& col) const;

  /// Get scale_factor for decimal columns. Returns 1 if not found or not decimal.
  int getScaleFactor(const std::string& table, const std::string& col) const;

  /// Find table that has this column (for enum lookup). Returns empty if not found.
  std::string getTableForColumn(const std::string& col) const;

  /// Convert a string value to int64 based on column type.
  /// Dispatches: date -> dateToId, enum -> lookupId, integer -> stoll, decimal -> scale and parse.
  /// \throws std::runtime_error on unknown type or value
  int64_t valueToInt64(const std::string& table, const std::string& col,
                       const std::string& str_val) const;

  /// ETL: Look up or register a string value for an enum column. Returns the ID.
  int registerOrLookup(const std::string& table, const std::string& col,
                       const std::string& str_val);

  void setFilePath(const std::string& path) { file_path_ = path; }
  void save();

 private:
  DictionaryManager() = default;

  struct ColumnInfo {
    DictColumnType type = DictColumnType::UNKNOWN;
    int radix_base = 8;
    int num_digits = 4;
    std::string epoch_start;  // for date
    int scale_factor = 1;     // for decimal
    std::map<std::string, int> mapping;
  };

  /// table -> column -> ColumnInfo
  std::map<std::string, std::map<std::string, ColumnInfo>> columns_;
  bool loaded_ = false;
  std::string version_;
  std::string file_path_;  // Path for load/save (required for registerOrLookup persist)
};

}  // namespace vaultdb

#endif  // VAULTDB_DICTIONARY_MANAGER_H_
