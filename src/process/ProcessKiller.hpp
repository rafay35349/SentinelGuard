#pragma once

// ---------------------------------------------------------------------------
// ProcessKiller – terminates a process by PID with safety checks.
//
// Critical system processes and PIDs 0 / 4 are always refused.
// TerminateProcess is never called for them under any circumstances.
// ---------------------------------------------------------------------------

#include "../core/Result.hpp"
#include <cstdint>

namespace sentinel::process {

// Terminate the process identified by pid.
//
// Steps performed internally:
//   1. Inspect the PID (ProcessInspector::inspectPid).
//   2. Refuse if isProtected == true.
//   3. OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION).
//   4. TerminateProcess(handle, exitCode=1).
//
// Returns Result<void>::ok() on success, or Result<void>::err(msg) where
// msg is a human-readable UTF-8 string with the Win32 error detail.
[[nodiscard]] sentinel::core::Result<void>
    terminateProcess(uint32_t pid);

} // namespace sentinel::process
