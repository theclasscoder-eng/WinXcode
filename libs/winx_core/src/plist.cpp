#include "winx/plist.hpp"

#include <cstring>
#include <fstream>
#include <iterator>

#include "winx/text.hpp"

namespace winx::plist {

Dict::Dict(std::initializer_list<Item> items) : items_(items) {}

const Value* Dict::find(std::string_view key) const {
    for (const auto& [name, value] : items_) {
        if (name == key) return &value;
    }
    return nullptr;
}

Value* Dict::find(std::string_view key) {
    for (auto& [name, value] : items_) {
        if (name == key) return &value;
    }
    return nullptr;
}

void Dict::set(std::string key, Value value) {
    if (Value* existing = find(key)) {
        *existing = std::move(value);
        return;
    }
    items_.emplace_back(std::move(key), std::move(value));
}

std::size_t Dict::size() const noexcept { return items_.size(); }

bool Dict::empty() const noexcept { return items_.empty(); }

bool Dict::operator==(const Dict& other) const { return items_ == other.items_; }

const std::string& Value::as_string() const {
    if (const auto* value = get_if<std::string>()) return *value;
    throw TypeError("plist value is not a string");
}

std::int64_t Value::as_int() const {
    if (const auto* value = get_if<std::int64_t>()) return *value;
    throw TypeError("plist value is not an integer");
}

bool Value::as_bool() const {
    if (const auto* value = get_if<bool>()) return *value;
    throw TypeError("plist value is not a boolean");
}

const Data& Value::as_data() const {
    if (const auto* value = get_if<Data>()) return *value;
    throw TypeError("plist value is not data");
}

const Array& Value::as_array() const {
    if (const auto* value = get_if<Array>()) return *value;
    throw TypeError("plist value is not an array");
}

const Dict& Value::as_dict() const {
    if (const auto* value = get_if<Dict>()) return *value;
    throw TypeError("plist value is not a dictionary");
}

const Value* Value::find(std::string_view key) const {
    const auto* dict = get_if<Dict>();
    return dict ? dict->find(key) : nullptr;
}

std::optional<std::string> Value::string_at(std::string_view key) const {
    const Value* value = find(key);
    if (!value) return std::nullopt;
    if (const auto* text = value->get_if<std::string>()) return *text;
    return std::nullopt;
}

std::optional<std::int64_t> Value::int_at(std::string_view key) const {
    const Value* value = find(key);
    if (!value) return std::nullopt;
    if (const auto* number = value->get_if<std::int64_t>()) return *number;
    return std::nullopt;
}

std::optional<bool> Value::bool_at(std::string_view key) const {
    const Value* value = find(key);
    if (!value) return std::nullopt;
    if (const auto* flag = value->get_if<bool>()) return *flag;
    return std::nullopt;
}

const Data* Value::data_at(std::string_view key) const {
    const Value* value = find(key);
    return value ? value->get_if<Data>() : nullptr;
}

bool Value::operator==(const Value& other) const { return storage_ == other.storage_; }

Value parse(std::span<const std::uint8_t> bytes) {
    static constexpr std::string_view kBinaryMagic = "bplist";
    if (bytes.size() >= kBinaryMagic.size() &&
        std::memcmp(bytes.data(), kBinaryMagic.data(), kBinaryMagic.size()) == 0) {
        return parse_binary(bytes);
    }
    return parse_xml(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

Value load_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + to_utf8(path.wstring()));
    const std::vector<char> bytes((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
    return parse(std::span(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()));
}

}  // namespace winx::plist
