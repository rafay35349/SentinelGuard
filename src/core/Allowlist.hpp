#pragma once

// ---------------------------------------------------------------------------
// sentinel::core::Allowlist
// Thread-safe process and category allowlist with file persistence.
// Protects against alert spam for trusted applications (e.g. Zoom, OBS).
// ---------------------------------------------------------------------------

#include "AlertEvent.hpp"

#include <cstdint>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel::core {

struct AllowlistEntry {
    std::wstring processName;       // e.g. "zoom.exe", "obs64.exe"
    bool         allowAll{ false }; // if true, suppresses all alert categories
    bool         allowProcess{ true };
    bool         allowClipboard{ false };
    bool         allowDevice{ true };
    bool         allowNetwork{ false };
    std::wstring note;              // user-supplied description/reason
};

class Allowlist {
public:
    Allowlist();
    explicit Allowlist(std::string persistencePath);
    ~Allowlist() = default;

    // Non-copyable, non-movable due to mutex
    Allowlist(const Allowlist&)            = delete;
    Allowlist& operator=(const Allowlist&) = delete;
    Allowlist(Allowlist&&)                 = delete;
    Allowlist& operator=(Allowlist&&)      = delete;

    // Query whether an event from processName is allowlisted for category
    [[nodiscard]] bool isAllowed(std::wstring_view processName,
                                 AlertCategory    category) const;

    // Add or update an entry (automatically saves if persistencePath is set)
    void addOrUpdate(AllowlistEntry entry);

    // Remove an entry by process name (case-insensitive)
    bool remove(std::wstring_view processName);

    // Get snapshot of all entries
    [[nodiscard]] std::vector<AllowlistEntry> getEntries() const;

    // Load from disk (returns true on success)
    bool loadFromFile(std::string_view filePath);

    // Save current entries to disk (returns true on success)
    bool saveToFile(std::string_view filePath) const;

    // Set or update default persistence file path
    void setPersistencePath(std::string path);

private:
    [[nodiscard]] static std::wstring toLower(std::wstring_view str);

    // Caller must already hold mutex_ exclusively.
    bool saveToFileLocked(std::string_view filePath) const;

    mutable std::shared_mutex   mutex_;
    std::vector<AllowlistEntry> entries_;
    std::string                 persistencePath_;
};

} // namespace sentinel::core
