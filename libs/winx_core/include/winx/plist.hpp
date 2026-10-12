#pragma once

#include <concepts>
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

// Apple property lists: XML read/write and binary (bplist00) read.
namespace winx::plist {

class Value;

struct Data {
    std::vector<std::uint8_t> bytes;
    bool operator==(const Data&) const = default;
};

// Seconds relative to 2001-01-01T00:00:00Z (Core Foundation absolute time).
struct Date {
    double seconds = 0.0;
    bool operator==(const Date&) const = default;
};

using Array = std::vector<Value>;

// Insertion-ordered dictionary.
class Dict {
public:
    using Item = std::pair<std::string, Value>;
    using Items = std::vector<Item>;

    Dict() = default;
    Dict(std::initializer_list<Item> items);

    const Value* find(std::string_view key) const;
    Value* find(std::string_view key);
    bool contains(std::string_view key) const { return find(key) != nullptr; }

    // Replaces the value if the key already exists.
    void set(std::string key, Value value);

    const Items& items() const noexcept { return items_; }
    // Defined out of line: Value is still incomplete here.
    std::size_t size() const noexcept;
    bool empty() const noexcept;

    bool operator==(const Dict& other) const;

private:
    Items items_;
};

class TypeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class ParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Value {
public:
    using Storage = std::variant<std::monostate, bool, std::int64_t, double, std::string, Data,
                                 Date, Array, Dict>;

    Value() = default;
    template <std::same_as<bool> T>
    Value(T value) : storage_(value) {}
    template <std::integral T>
        requires(!std::same_as<T, bool>)
    Value(T value) : storage_(static_cast<std::int64_t>(value)) {}
    Value(double value) : storage_(value) {}
    Value(const char* value) : storage_(std::string(value)) {}
    Value(std::string_view value) : storage_(std::string(value)) {}
    Value(std::string value) : storage_(std::move(value)) {}
    Value(Data value) : storage_(std::move(value)) {}
    Value(Date value) : storage_(value) {}
    Value(Array value) : storage_(std::move(value)) {}
    Value(Dict value) : storage_(std::move(value)) {}

    bool is_null() const noexcept { return std::holds_alternative<std::monostate>(storage_); }
    template <class T>
    bool is() const noexcept {
        return std::holds_alternative<T>(storage_);
    }
    template <class T>
    const T* get_if() const noexcept {
        return std::get_if<T>(&storage_);
    }
    template <class T>
    T* get_if() noexcept {
        return std::get_if<T>(&storage_);
    }
    const Storage& storage() const noexcept { return storage_; }

    // Throw TypeError when the value holds a different type.
    const std::string& as_string() const;
    std::int64_t as_int() const;
    bool as_bool() const;
    const Data& as_data() const;
    const Array& as_array() const;
    const Dict& as_dict() const;

    // Dictionary lookups; all return empty when this is not a dictionary, the
    // key is missing, or the entry has a different type.
    const Value* find(std::string_view key) const;
    std::optional<std::string> string_at(std::string_view key) const;
    std::optional<std::int64_t> int_at(std::string_view key) const;
    std::optional<bool> bool_at(std::string_view key) const;
    const Data* data_at(std::string_view key) const;

    bool operator==(const Value& other) const;

private:
    Storage storage_;
};

Value parse_xml(std::string_view text);
Value parse_binary(std::span<const std::uint8_t> bytes);
// Detects the format from the leading bytes.
Value parse(std::span<const std::uint8_t> bytes);
Value load_file(const std::filesystem::path& path);

std::string to_xml(const Value& value);
// bplist00, the form iOS expects for a bundle's Info.plist.
std::vector<std::uint8_t> to_binary(const Value& value);

}  // namespace winx::plist
