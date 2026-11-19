// SentinelGuard – tests/VerifyMilestone2.cpp
// Automated verification suite for Milestone 2:
// 1. Inspect & terminate a disposable notepad.exe target
// 2. Critical process guard check on PID 0, PID 4, and explorer.exe
// 3. Non-existent PID check (e.g. 999999) and GetLastError() formatting
// 4. RAII safety and exit code verification

#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <windows.h>
#include <tlhelp32.h>

#include "core/Win32Handle.hpp"
#include "core/Win32Utils.hpp"
#include "core/Result.hpp"
#include "process/ProcessInspector.hpp"
#include "process/ProcessKiller.hpp"

namespace {

int g_failures = 0;

void reportTest(bool passed, const std::string& name, const std::string& detail = "")
{
    if (passed) {
        std::cout << "  [PASS] " << name;
        if (!detail.empty()) std::cout << " (" << detail << ")";
        std::cout << "\n";
    } else {
        std::cout << "  [FAIL] " << name;
        if (!detail.empty()) std::cout << " -> " << detail;
        std::cout << "\n";
        ++g_failures;
    }
}

// Helper to find running explorer.exe PID for read-only guard test
uint32_t findExplorerPid()
{
    sentinel::core::UniqueHandle snap{ ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if (!snap) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap.get(), &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                return static_cast<uint32_t>(pe.th32ProcessID);
            }
        } while (::Process32NextW(snap.get(), &pe));
    }
    return 0;
}

} // anonymous namespace

int main()
{
    std::cout << "========================================================\n";
    std::cout << "  SentinelGuard – Milestone 2 Automated Verification\n";
    std::cout << "========================================================\n\n";

    // -------------------------------------------------------------------------
    // TEST SUITE 1: Disposable Process Lifecycle (notepad.exe)
    // -------------------------------------------------------------------------
    std::cout << "[Suite 1] Disposable Target Lifecycle (notepad.exe)\n";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    wchar_t cmdLine[] = L"notepad.exe";
    const BOOL launched = ::CreateProcessW(
        nullptr, cmdLine, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    if (!launched) {
        reportTest(false, "Launch disposable notepad.exe",
                   "CreateProcessW failed: " + sentinel::core::formatWin32Error(::GetLastError()));
        return 1;
    }

    // Immediately wrap raw handles in RAII UniqueHandle
    sentinel::core::UniqueHandle childProcess{ pi.hProcess };
    sentinel::core::UniqueHandle childThread{ pi.hThread };
    const uint32_t notepadPid = static_cast<uint32_t>(pi.dwProcessId);

    reportTest(true, "Launch disposable notepad.exe", "PID " + std::to_string(notepadPid));

    // Test 1.1: Inspect notepad.exe
    const auto inspectResult = sentinel::process::inspectPid(notepadPid);
    reportTest(inspectResult.isOk(), "inspectPid(notepadPid) succeeds");

    if (inspectResult.isOk()) {
        const auto& info = inspectResult.value();
        reportTest(info.pid == notepadPid, "ProcessInfo PID matches", std::to_string(info.pid));
        reportTest(_wcsicmp(info.name.c_str(), L"notepad.exe") == 0,
                   "Executable name is notepad.exe",
                   sentinel::core::wideToUtf8(info.name));
        reportTest(!info.fullPath.empty(), "Full path resolved",
                   sentinel::core::wideToUtf8(info.fullPath));
        reportTest(info.isProtected == false, "notepad.exe is NOT flagged as protected");
    }

    // Test 1.2: Terminate notepad.exe using ProcessKiller
    const auto killResult = sentinel::process::terminateProcess(notepadPid);
    reportTest(killResult.isOk(), "terminateProcess(notepadPid) succeeds");

    // Test 1.3: Verify process actually terminated
    const DWORD waitStatus = ::WaitForSingleObject(childProcess.get(), 2000);
    reportTest(waitStatus == WAIT_OBJECT_0, "notepad.exe process object signaled (terminated)");

    DWORD exitCode = 0;
    if (::GetExitCodeProcess(childProcess.get(), &exitCode)) {
        reportTest(exitCode == 1, "Exit code matches kExitCode (1)", std::to_string(exitCode));
    }

    // -------------------------------------------------------------------------
    // TEST SUITE 2: Critical System Process Guard
    // -------------------------------------------------------------------------
    std::cout << "\n[Suite 2] Critical System Process Protection Guard\n";

    // Test 2.1: PID 0 (System Idle)
    {
        const auto rInspect = sentinel::process::inspectPid(0);
        reportTest(rInspect.isOk() && rInspect.value().isProtected,
                   "PID 0 flagged as isProtected == true");

        const auto rKill = sentinel::process::terminateProcess(0);
        reportTest(rKill.isErr(), "terminateProcess(0) blocked", rKill.isErr() ? rKill.error() : "");
    }

    // Test 2.2: PID 4 (System)
    {
        const auto rInspect = sentinel::process::inspectPid(4);
        reportTest(rInspect.isOk() && rInspect.value().isProtected,
                   "PID 4 flagged as isProtected == true");

        const auto rKill = sentinel::process::terminateProcess(4);
        reportTest(rKill.isErr(), "terminateProcess(4) blocked", rKill.isErr() ? rKill.error() : "");
    }

    // Test 2.3: All 7 critical system process names tested explicitly (case-insensitive)
    {
        const std::array<std::wstring_view, 7> criticalList{{
            L"csrss.exe", L"lsass.exe", L"wininit.exe",
            L"services.exe", L"svchost.exe", L"dwm.exe", L"explorer.exe"
        }};

        bool allNamesProtected = true;
        for (const auto& name : criticalList) {
            if (!sentinel::process::isProtectedProcessName(name)) {
                allNamesProtected = false;
                break;
            }
        }
        reportTest(allNamesProtected, "All 7 critical system process names recognized");

        // Case-insensitivity check (e.g. ExPlOrEr.EXE, SVCHOST.EXE)
        const bool caseInsensitiveMatch =
            sentinel::process::isProtectedProcessName(L"ExPlOrEr.EXE") &&
            sentinel::process::isProtectedProcessName(L"SVCHOST.exe") &&
            sentinel::process::isProtectedProcessName(L"CsRsS.Exe");
        reportTest(caseInsensitiveMatch, "Critical process name matching is case-insensitive");

        // False positive check on non-critical processes
        const bool nonCriticalsAllowed =
            !sentinel::process::isProtectedProcessName(L"notepad.exe") &&
            !sentinel::process::isProtectedProcessName(L"calculator.exe") &&
            !sentinel::process::isProtectedProcessName(L"my_custom_app.exe");
        reportTest(nonCriticalsAllowed, "Non-critical processes are not blocked");
    }

    // -------------------------------------------------------------------------
    // TEST SUITE 3: Non-Existent & Invalid PID Error Handling
    // -------------------------------------------------------------------------
    std::cout << "\n[Suite 3] Non-Existent PID & GetLastError() Diagnostics\n";

    constexpr uint32_t kBogusPid = 999999;
    const auto bogusInspect = sentinel::process::inspectPid(kBogusPid);
    reportTest(bogusInspect.isErr(),
               "inspectPid(999999) fails cleanly",
               bogusInspect.isErr() ? bogusInspect.error() : "");

    const auto bogusKill = sentinel::process::terminateProcess(kBogusPid);
    reportTest(bogusKill.isErr(),
               "terminateProcess(999999) fails cleanly",
               bogusKill.isErr() ? bogusKill.error() : "");

    // -------------------------------------------------------------------------
    // Final Summary
    // -------------------------------------------------------------------------
    std::cout << "\n========================================================\n";
    if (g_failures == 0) {
        std::cout << "  ALL VERIFICATION TESTS PASSED (0 failures)\n";
    } else {
        std::cout << "  VERIFICATION FAILED: " << g_failures << " test(s) failed\n";
    }
    std::cout << "========================================================\n";

    return (g_failures == 0) ? 0 : 1;
}
