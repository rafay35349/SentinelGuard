#pragma once

// ---------------------------------------------------------------------------
// Win32 string utility helpers shared across process/ translation units.
// Keep this header small – only include it from .cpp files that already
// have a <windows.h> dependency.
// ---------------------------------------------------------------------------

#include <windows.h>
#include <string>
#include <string_view>

namespace sentinel::core {

// ---------------------------------------------------------------------------
// formatWin32Error – convert a Win32 error code to a UTF-8 display string.
// Trims the trailing CR/LF that FormatMessage appends.
// ---------------------------------------------------------------------------
[[nodiscard]] inline std::string formatWin32Error(DWORD code)
{
    char buf[512]{};
    const DWORD len = ::FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        0,
        buf,
        static_cast<DWORD>(sizeof(buf) - 1),
        nullptr);

    std::string msg = (len > 0)
        ? std::string(buf, len)
        : ("Error code " + std::to_string(code));

    // Trim trailing whitespace / newlines added by FormatMessage.
    while (!msg.empty() &&
           (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' '))
    {
        msg.pop_back();
    }
    return msg;
}

// ---------------------------------------------------------------------------
// wideToUtf8 – lossless wide-string to UTF-8 conversion via WinAPI.
// Returns an empty string on empty input or conversion failure.
// ---------------------------------------------------------------------------
[[nodiscard]] inline std::string wideToUtf8(std::wstring_view wstr)
{
    if (wstr.empty()) return {};

    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.data(), static_cast<int>(wstr.size()),
        nullptr, 0,
        nullptr, nullptr);

    if (needed <= 0) return {};

    std::string result(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.data(), static_cast<int>(wstr.size()),
        result.data(), needed,
        nullptr, nullptr);
    return result;
}

// ---------------------------------------------------------------------------
// utf8ToWide – lossless UTF-8 to wide-string conversion via WinAPI.
// Returns an empty wstring on empty input or conversion failure.
// ---------------------------------------------------------------------------
[[nodiscard]] inline std::wstring utf8ToWide(std::string_view str)
{
    if (str.empty()) return {};

    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0,
        str.data(), static_cast<int>(str.size()),
        nullptr, 0);

    if (needed <= 0) return {};

    std::wstring result(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0,
        str.data(), static_cast<int>(str.size()),
        result.data(), needed);
    return result;
}

} // namespace sentinel::core
