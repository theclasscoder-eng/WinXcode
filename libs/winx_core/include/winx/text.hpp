#pragma once

#include <string>
#include <string_view>

namespace winx {

std::string to_utf8(std::wstring_view wide);
std::wstring to_wide(std::string_view utf8);

void append_utf8(std::string& out, char32_t code_point);

// Human-readable text for a Win32 or WinSock error code, as UTF-8.
std::string win32_error_message(unsigned long code);

}  // namespace winx
