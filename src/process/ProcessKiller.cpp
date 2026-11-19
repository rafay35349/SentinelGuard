// SentinelGuard – src/process/ProcessKiller.cpp
// TerminateProcess with critical system process guard and formatted GetLastError().
// All Win32 HANDLEs wrapped in UniqueHandle. Zero raw new/delete.

#include "ProcessKiller.hpp"
#include "ProcessInspector.hpp"

#include <windows.h>
#include <string>

#include "../core/Win32Handle.hpp"
#include "../core/Win32Utils.hpp"

namespace sentinel::process {

sentinel::core::Result<void> terminateProcess(uint32_t pid)
{
    // 1. Inspect first to verify existence and check critical process guard
    const auto inspectRes = inspectPid(pid);
    if (inspectRes.isErr()) {
        return sentinel::core::Result<void>::err(
            "Pre-termination inspection failed: " + inspectRes.error());
    }

    const ProcessInfo& info = inspectRes.value();
    if (info.isProtected) {
        return sentinel::core::Result<void>::err(
            "Refused to terminate critical system process: " +
            sentinel::core::wideToUtf8(info.name) +
            " (PID " + std::to_string(pid) + ")");
    }

    // 2. Open process handle with terminate permissions wrapped in UniqueHandle
    sentinel::core::UniqueHandle proc{
        ::OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                      FALSE,
                      static_cast<DWORD>(pid))};

    if (!proc) {
        const DWORD err = ::GetLastError();
        return sentinel::core::Result<void>::err(
            "OpenProcess(PROCESS_TERMINATE) failed for PID " +
            std::to_string(pid) + ": " + sentinel::core::formatWin32Error(err));
    }

    // 3. Terminate process with explicit non-zero exit code
    constexpr UINT kExitCode = 1;
    if (!::TerminateProcess(proc.get(), kExitCode)) {
        const DWORD err = ::GetLastError();
        return sentinel::core::Result<void>::err(
            "TerminateProcess failed for PID " + std::to_string(pid) +
            ": " + sentinel::core::formatWin32Error(err));
    }

    return sentinel::core::Result<void>::ok();
}

} // namespace sentinel::process
