#include "swift_language.hpp"

namespace winx::ide {
namespace {

bool is_digit(ImWchar c) { return c >= '0' && c <= '9'; }
bool is_hex(ImWchar c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
bool is_identifier_start(ImWchar c) {
    // Swift allows most of Unicode in identifiers; anything non-ASCII counts.
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$' || c >= 0x80;
}
bool is_identifier_part(ImWchar c) { return is_identifier_start(c) || is_digit(c); }

}  // namespace

TextEditor::Iterator swift_identifier(TextEditor::Iterator start, TextEditor::Iterator end) {
    if (start == end || !is_identifier_start(*start)) return start;
    TextEditor::Iterator i = start;
    while (i != end && is_identifier_part(*i)) ++i;
    return i;
}

TextEditor::Iterator swift_number(TextEditor::Iterator start, TextEditor::Iterator end) {
    if (start == end || !is_digit(*start)) return start;
    TextEditor::Iterator i = start;
    const auto peek = [&](TextEditor::Iterator at) -> ImWchar {
        ++at;
        return at != end ? *at : 0;
    };

    if (*i == '0' && (peek(i) == 'x' || peek(i) == 'b' || peek(i) == 'o')) {
        const ImWchar radix = peek(i);
        ++i;
        ++i;
        while (i != end && (*i == '_' || (radix == 'x' ? is_hex(*i) : is_digit(*i)))) ++i;
        // Hexadecimal floating point: 0x1.8p3
        if (radix == 'x' && i != end && *i == '.' && is_hex(peek(i))) {
            ++i;
            while (i != end && (is_hex(*i) || *i == '_')) ++i;
        }
        if (radix == 'x' && i != end && (*i == 'p' || *i == 'P')) {
            ++i;
            if (i != end && (*i == '+' || *i == '-')) ++i;
            while (i != end && is_digit(*i)) ++i;
        }
        return i;
    }

    while (i != end && (is_digit(*i) || *i == '_')) ++i;
    // A fraction needs a digit after the dot, so that "1.description" and
    // "0..<5" keep their dots.
    if (i != end && *i == '.' && is_digit(peek(i))) {
        ++i;
        while (i != end && (is_digit(*i) || *i == '_')) ++i;
    }
    if (i != end && (*i == 'e' || *i == 'E')) {
        TextEditor::Iterator exponent = i;
        ++exponent;
        if (exponent != end && (*exponent == '+' || *exponent == '-')) ++exponent;
        if (exponent != end && is_digit(*exponent)) {
            while (exponent != end && is_digit(*exponent)) ++exponent;
            i = exponent;
        }
    }
    return i;
}

bool swift_punctuation(ImWchar c) {
    switch (c) {
        case '[': case ']': case '{': case '}': case '(': case ')': case '<': case '>':
        case '!': case '%': case '^': case '&': case '*': case '-': case '+': case '=':
        case '~': case '|': case '/': case '?': case ':': case ';': case ',': case '.':
        case '@': case '\\':
            return true;
        default:
            return false;
    }
}

const TextEditor::Language* swift_language() {
    static const TextEditor::Language language = [] {
        TextEditor::Language swift;
        swift.name = "Swift";
        swift.preprocess = '#';  // #if, #available, #Preview and other macros
        swift.singleLineComment = "//";
        swift.commentStart = "/*";
        swift.commentEnd = "*/";
        swift.hasDoubleQuotedStrings = true;
        swift.otherStringStart = "\"\"\"";
        swift.otherStringEnd = "\"\"\"";
        swift.stringEscape = '\\';

        swift.keywords = {
            "as",       "async",     "await",    "break",    "case",     "catch",   "continue",
            "default",  "defer",     "do",       "else",     "fallthrough", "for",  "guard",
            "if",       "in",        "is",       "repeat",   "return",   "switch",  "throw",
            "throws",   "rethrows",  "try",      "where",    "while",    "true",    "false",
            "nil",      "self",      "Self",     "super",    "some",     "any",     "inout",
            "get",      "set",       "willSet",  "didSet",   "consume",  "borrowing", "consuming",
            "each",     "repeat",    "discard",  "nonisolated", "isolated", "sending"};
        swift.declarations = {
            "actor",    "associatedtype", "class",  "deinit",  "enum",     "extension", "func",
            "import",   "init",      "let",      "macro",    "operator", "precedencegroup",
            "protocol", "struct",    "subscript", "typealias", "var",     "public",  "private",
            "fileprivate", "internal", "open",   "package",  "static",   "final",   "override",
            "mutating", "nonmutating", "lazy",   "weak",     "unowned",  "required", "convenience",
            "dynamic",  "indirect",  "optional", "prefix",   "postfix",  "infix"};
        swift.identifiers = {
            "Int",      "Int8",      "Int16",    "Int32",    "Int64",    "UInt",    "UInt8",
            "UInt16",   "UInt32",    "UInt64",   "Float",    "Double",   "Bool",    "String",
            "Character", "Array",    "Dictionary", "Set",    "Optional", "Result",  "Void",
            "Never",    "Any",       "AnyObject", "Error",   "Data",     "Date",    "URL",
            "UUID",     "Task",      "MainActor", "Sendable", "Codable", "Identifiable",
            "Hashable", "Equatable", "Comparable", "View",   "App",      "Scene",   "State",
            "Binding",  "Observable", "Environment", "Published", "ObservedObject",
            "StateObject", "Text",   "Image",    "Button",   "VStack",   "HStack",  "ZStack",
            "List",     "NavigationStack", "WindowGroup", "Color", "Font", "print"};

        swift.isPunctuation = swift_punctuation;
        swift.getIdentifier = swift_identifier;
        swift.getNumber = swift_number;
        return swift;
    }();
    return &language;
}

TextEditor::Palette editor_palette() {
    TextEditor::Palette palette = TextEditor::GetDarkPalette();
    const auto set = [&](TextEditor::Color color, ImU32 value) {
        palette[static_cast<std::size_t>(color)] = value;
    };
    // IM_COL32 is R, G, B, A.
    set(TextEditor::Color::text, IM_COL32(223, 223, 224, 255));
    set(TextEditor::Color::keyword, IM_COL32(255, 122, 178, 255));
    set(TextEditor::Color::declaration, IM_COL32(255, 122, 178, 255));
    set(TextEditor::Color::number, IM_COL32(217, 201, 124, 255));
    set(TextEditor::Color::string, IM_COL32(255, 129, 112, 255));
    set(TextEditor::Color::punctuation, IM_COL32(200, 200, 205, 255));
    set(TextEditor::Color::preprocessor, IM_COL32(255, 161, 79, 255));
    set(TextEditor::Color::identifier, IM_COL32(223, 223, 224, 255));
    set(TextEditor::Color::knownIdentifier, IM_COL32(172, 242, 228, 255));
    set(TextEditor::Color::comment, IM_COL32(127, 140, 152, 255));
    set(TextEditor::Color::background, IM_COL32(41, 42, 48, 255));
    set(TextEditor::Color::cursor, IM_COL32(255, 255, 255, 255));
    set(TextEditor::Color::selection, IM_COL32(100, 110, 130, 150));
    set(TextEditor::Color::lineNumber, IM_COL32(116, 120, 130, 255));
    set(TextEditor::Color::currentLineNumber, IM_COL32(223, 223, 224, 255));
    set(TextEditor::Color::currentLineHighlight, IM_COL32(47, 50, 57, 255));
    set(TextEditor::Color::currentLineHighlightBorder, IM_COL32(47, 50, 57, 255));
    return palette;
}

}  // namespace winx::ide
