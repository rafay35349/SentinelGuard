// SentinelGuard – src/core/Allowlist.cpp
// Thread-safe process and category allowlist with human-readable persistence.

#include "Allowlist.hpp"
#include "Win32Utils.hpp"

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <sstream>

namespace sentinel::core {

namespace {

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
    if (!persistencePath_.empty()) {
        loadFromFile(persistencePath_);
    }
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
        saveToFileLocked(persistencePath_);
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
        saveToFileLocked(persistencePath_);
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
    // Snapshot under a shared lock so a concurrent writer cannot mutate
    // entries_ mid-write. saveToFileLocked() is used by mutating paths, which
    // already hold the exclusive lock (std::shared_mutex is not recursive).
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return saveToFileLocked(filePath);
}

bool Allowlist::saveToFileLocked(std::string_view filePath) const
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

    return out.good();
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

    std::unique_lock<std::shared_mutex> lock(mutex_);
    entries_ = std::move(loaded);
    return true;
}

} // namespace sentinel::core
