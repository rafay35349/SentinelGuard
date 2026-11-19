#pragma once

// ---------------------------------------------------------------------------
// ProcessInspector – PID → ProcessInfo resolution.
//
// All Win32 handles are wrapped in sentinel::core::UniqueHandle.
// Error messages are UTF-8 strings suitable for direct ImGui display.
// ---------------------------------------------------------------------------

#include "../core/Result.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace sentinel::process {

// ---------------------------------------------------------------------------
// ProcessInfo – plain-data record for one running process.
// ---------------------------------------------------------------------------
struct ProcessInfo {
    uint32_t     pid{ 0 };
    std::wstring name;               // base executable name, e.g. "explorer.exe"
    std::wstring fullPath;           // full image path (empty for snapshot-only records)
    bool         isProtected{ false }; // true → critical system process, never terminate
};

// Inspect a single PID via OpenProcess + QueryFullProcessImageNameW.
// PIDs 0 and 4 are returned as protected pseudo-process records.
// Returns ProcessInfo on success, or a UTF-8 error string on failure.
[[nodiscard]] sentinel::core::Result<ProcessInfo>
    inspectPid(uint32_t pid);

// Lightweight snapshot of all running processes (Toolhelp32).
// Records contain name + pid only; fullPath is empty.
// Returns list on success, or a UTF-8 error string on failure.
[[nodiscard]] sentinel::core::Result<std::vector<ProcessInfo>>
    enumerateProcesses();

} // namespace sentinel::process
