// SentinelGuard – src/process/ProcessInspector.cpp
// PID → ProcessInfo resolution via OpenProcess + QueryFullProcessImageNameW.
// All Win32 HANDLEs wrapped in UniqueHandle. Zero raw new/delete.

#include "ProcessInspector.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <string_view>

#include "../core/Win32Handle.hpp"
#include "../core/Win32Utils.hpp"

namespace sentinel::process {

// ── Internal constants & helpers ────────────────────────────────────────────
namespace {

constexpr uint32_t    kIdlePid    = 0;
constexpr uint32_t    kSystemPid  = 4;
constexpr std::size_t kPathBufLen = MAX_PATH * 2; // 520 wchar_t

constexpr std::array<std::wstring_view, 7> kProtectedNames{{
    L"csrss.exe",   L"lsass.exe",  L"wininit.exe",
    L"services.exe", L"svchost.exe", L"dwm.exe", L"explorer.exe"
}};

[[nodiscard]] std::wstring extractBaseName(std::wstring_view path)
{
    const auto pos = path.rfind(L'\\');
    return std::wstring(
        pos == std::wstring_view::npos ? path : path.substr(pos + 1));
}

[[nodiscard]] bool isProtectedName(std::wstring_view name)
{
    std::wstring lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); });
    for (std::wstring_view prot : kProtectedNames) {
        if (lower == prot) return true;
    }
    return false;
}

} // anonymous namespace

// ── inspectPid ───────────────────────────────────────────────────────────────
sentinel::core::Result<ProcessInfo> inspectPid(uint32_t pid)
{
    // Pseudo-processes: return a protected record immediately.
    if (pid == kIdlePid || pid == kSystemPid) {
        ProcessInfo info{};
        info.pid         = pid;
        info.name        = (pid == kIdlePid) ? L"[System Idle Process]" : L"[System]";
        info.isProtected = true;
        return sentinel::core::Result<ProcessInfo>::ok(std::move(info));
    }

    sentinel::core::UniqueHandle proc{
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                      FALSE, static_cast<DWORD>(pid))};

    if (!proc) {
        const DWORD err = ::GetLastError();
        return sentinel::core::Result<ProcessInfo>::err(
            "OpenProcess failed for PID " + std::to_string(pid) +
            ": " + sentinel::core::formatWin32Error(err));
    }

    wchar_t pathBuf[kPathBufLen]{};
    DWORD   pathLen = static_cast<DWORD>(kPathBufLen);

    if (!::QueryFullProcessImageNameW(proc.get(), 0, pathBuf, &pathLen)) {
        const DWORD err = ::GetLastError();
        return sentinel::core::Result<ProcessInfo>::err(
            "QueryFullProcessImageNameW failed for PID " + std::to_string(pid) +
            ": " + sentinel::core::formatWin32Error(err));
    }

    ProcessInfo info{};
    info.pid         = pid;
    info.fullPath    = std::wstring(pathBuf, pathLen);
    info.name        = extractBaseName(info.fullPath);
    info.isProtected = isProtectedName(info.name);
    return sentinel::core::Result<ProcessInfo>::ok(std::move(info));
}

// ── enumerateProcesses ───────────────────────────────────────────────────────
sentinel::core::Result<std::vector<ProcessInfo>> enumerateProcesses()
{
    sentinel::core::UniqueHandle snap{
        ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};

    if (!snap) {
        return sentinel::core::Result<std::vector<ProcessInfo>>::err(
            "CreateToolhelp32Snapshot failed: " +
            sentinel::core::formatWin32Error(::GetLastError()));
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!::Process32FirstW(snap.get(), &entry)) {
        return sentinel::core::Result<std::vector<ProcessInfo>>::err(
            "Process32FirstW failed: " +
            sentinel::core::formatWin32Error(::GetLastError()));
    }

    std::vector<ProcessInfo> result;
    result.reserve(256);

    do {
        ProcessInfo info{};
        info.pid         = static_cast<uint32_t>(entry.th32ProcessID);
        info.name        = entry.szExeFile;
        info.isProtected = isProtectedName(info.name)
                        || info.pid == kIdlePid
                        || info.pid == kSystemPid;
        result.push_back(std::move(info));
    } while (::Process32NextW(snap.get(), &entry));

    return sentinel::core::Result<std::vector<ProcessInfo>>::ok(std::move(result));
}

} // namespace sentinel::process
