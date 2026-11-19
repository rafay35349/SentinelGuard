// SentinelGuard – src/core/Allowlist.cpp
// Thread-safe process and category allowlist with human-readable persistence.

#include "Allowlist.hpp"

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <sstream>

namespace sentinel::core {

namespace {

[[nodiscard]] std::string wideToUtf8(std::wstring_view wstr)
{
    std::string out;
    out.reserve(wstr.size());
    for (const wchar_t wc : wstr) {
        if (wc < 0x80) {
            out.push_back(static_cast<char>(wc));
        } else if (wc < 0x800) {
            out.push_back(static_cast<char>(0xC0 | ((wc >> 6) & 0x1F)));
            out.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | ((wc >> 12) & 0x0F)));
            out.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        }
    }
    return out;
}

[[nodiscard]] std::wstring utf8ToWide(std::string_view str)
{
    std::wstring out;
    out.reserve(str.size());
    for (std::size_t i = 0; i < str.size();) {
        const auto c = static_cast<unsigned char>(str[i]);
        if (c < 0x80) {
            out.push_back(static_cast<wchar_t>(c));
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < str.size()) {
            const auto c2 = static_cast<unsigned char>(str[i + 1]);
            out.push_back(static_cast<wchar_t>(((c & 0x1F) << 6) | (c2 & 0x3F)));
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < str.size()) {
            const auto c2 = static_cast<unsigned char>(str[i + 1]);
            const auto c3 = static_cast<unsigned char>(str[i + 2]);
            out.push_back(static_cast<wchar_t>(((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F)));
            i += 3;
        } else {
            out.push_back(static_cast<wchar_t>(c));
            ++i;
        }
    }
    return out;
}

[[nodiscard]] std::wstring extractBaseName(std::wstring_view path)
{
    const auto slash1 = path.rfind(L'\\');
    const auto slash2 = path.rfind(L'/');
    auto pos = (slash1 == std::wstring_view::npos) ? slash2 : slash1;
    if (slash1 != std::wstring_view::npos && slash2 != std::wstring_view::npos) {
        pos = (std::max)(slash1, slash2);
    }
    return std::wstring(pos == std::wstring_view::npos ? path : path.substr(pos + 1));
}

} // anonymous namespace

Allowlist::Allowlist() = default;

Allowlist::Allowlist(std::string persistencePath)
    : persistencePath_(std::move(persistencePath))
{
    loadFromFile(persistencePath_);
}

std::wstring Allowlist::toLower(std::wstring_view str)
{
    std::wstring result(str);
    std::transform(result.begin(), result.end(), result.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return result;
}

void Allowlist::setPersistencePath(std::string path)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    persistencePath_ = std::move(path);
}

bool Allowlist::isAllowed(std::wstring_view processName, AlertCategory category) const
{
    if (processName.empty()) {
        return false;
    }

    const std::wstring targetBase = toLower(extractBaseName(processName));

    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& entry : entries_) {
        if (toLower(entry.processName) == targetBase) {
            if (entry.allowAll) return true;
            switch (category) {
                case AlertCategory::Process:   return entry.allowProcess;
                case AlertCategory::Clipboard: return entry.allowClipboard;
                case AlertCategory::Device:    return entry.allowDevice;
                case AlertCategory::Network:   return entry.allowNetwork;
                default:                       return false;
            }
        }
    }
    return false;
}

void Allowlist::addOrUpdate(AllowlistEntry entry)
{
    const std::wstring baseTarget = toLower(extractBaseName(entry.processName));
    entry.processName = extractBaseName(entry.processName);

    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = std::find_if(entries_.begin(), entries_.end(), [&](const AllowlistEntry& e) {
        return toLower(e.processName) == baseTarget;
    });

    if (it != entries_.end()) {
        *it = std::move(entry);
    } else {
        entries_.push_back(std::move(entry));
    }

    if (!persistencePath_.empty()) {
        saveToFile(persistencePath_);
    }
}

bool Allowlist::remove(std::wstring_view processName)
{
    const std::wstring baseTarget = toLower(extractBaseName(processName));

    std::unique_lock<std::shared_mutex> lock(mutex_);
    const auto origSize = entries_.size();
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(), [&](const AllowlistEntry& e) {
            return toLower(e.processName) == baseTarget;
        }),
        entries_.end());

    const bool removed = (entries_.size() < origSize);
    if (removed && !persistencePath_.empty()) {
        saveToFile(persistencePath_);
    }
    return removed;
}

std::vector<AllowlistEntry> Allowlist::getEntries() const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return entries_;
}

bool Allowlist::saveToFile(std::string_view filePath) const
{
    const std::string path(filePath);
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    out << "# SentinelGuard Allowlist Persistence Format v1\n";
    out << "# Format: ProcessName|AllowAll|AllowProcess|AllowClipboard|AllowDevice|AllowNetwork|Note\n";

    for (const auto& e : entries_) {
        out << wideToUtf8(e.processName) << "|"
            << (e.allowAll ? "1" : "0") << "|"
            << (e.allowProcess ? "1" : "0") << "|"
            << (e.allowClipboard ? "1" : "0") << "|"
            << (e.allowDevice ? "1" : "0") << "|"
            << (e.allowNetwork ? "1" : "0") << "|"
            << wideToUtf8(e.note) << "\n";
    }

    return true;
}

bool Allowlist::loadFromFile(std::string_view filePath)
{
    const std::string path(filePath);
    std::ifstream in(path);
    if (!in.is_open()) {
        return false;
    }

    std::vector<AllowlistEntry> loaded;
    std::string line;

    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::stringstream ss(line);
        std::string part;
        std::vector<std::string> tokens;
        while (std::getline(ss, part, '|')) {
            tokens.push_back(part);
        }

        if (tokens.size() >= 6) {
            AllowlistEntry entry{};
            entry.processName    = utf8ToWide(tokens[0]);
            entry.allowAll       = (tokens[1] == "1");
            entry.allowProcess   = (tokens[2] == "1");
            entry.allowClipboard = (tokens[3] == "1");
            entry.allowDevice    = (tokens[4] == "1");
            entry.allowNetwork   = (tokens[5] == "1");
            if (tokens.size() >= 7) {
                entry.note = utf8ToWide(tokens[6]);
            }
            loaded.push_back(std::move(entry));
        }
    }

    entries_ = std::move(loaded);
    return true;
}

} // namespace sentinel::core
