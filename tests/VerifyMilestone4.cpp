// SentinelGuard – tests/VerifyMilestone4.cpp
// Automated verification suite for Milestone 4:
// 1. Allowlist policy matching, case-insensitivity, category filters
// 2. Allowlist file persistence save/load cycle
// 3. DeviceMonitor thread lifecycle & non-blocking scanning

#include <iostream>
#include <string>
#include <string_view>
#include <chrono>
#include <thread>
#include <cstdio>

#include "core/AlertEvent.hpp"
#include "core/Allowlist.hpp"
#include "core/EventBus.hpp"
#include "monitors/DeviceMonitor.hpp"

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

} // anonymous namespace

int main()
{
    std::cout << "========================================================\n";
    std::cout << "  SentinelGuard – Milestone 4 Automated Verification\n";
    std::cout << "========================================================\n\n";

    // -------------------------------------------------------------------------
    // TEST SUITE 1: Allowlist Matching & Category Rules
    // -------------------------------------------------------------------------
    std::cout << "[Suite 1] Allowlist Policy Matching & Filtering\n";

    sentinel::core::Allowlist allowlist;

    // 1.1: Add Zoom with Device-only allowed
    sentinel::core::AllowlistEntry zoomEntry{};
    zoomEntry.processName    = L"zoom.exe";
    zoomEntry.allowAll       = false;
    zoomEntry.allowDevice    = true;
    zoomEntry.allowProcess   = false;
    zoomEntry.allowClipboard = false;
    zoomEntry.allowNetwork   = false;
    zoomEntry.note           = L"Video meeting tool";
    allowlist.addOrUpdate(zoomEntry);

    reportTest(allowlist.isAllowed(L"zoom.exe", sentinel::core::AlertCategory::Device),
               "zoom.exe is allowed for Device");
    reportTest(!allowlist.isAllowed(L"zoom.exe", sentinel::core::AlertCategory::Clipboard),
               "zoom.exe is NOT allowed for Clipboard");
    reportTest(!allowlist.isAllowed(L"zoom.exe", sentinel::core::AlertCategory::Process),
               "zoom.exe is NOT allowed for Process");

    // 1.2: Case-insensitivity check (e.g. "ZOOM.EXE", "Zoom.exe", full path)
    reportTest(allowlist.isAllowed(L"ZOOM.EXE", sentinel::core::AlertCategory::Device),
               "Case-insensitive match: ZOOM.EXE allowed for Device");
    reportTest(allowlist.isAllowed(L"C:\\Program Files\\Zoom\\bin\\Zoom.exe", sentinel::core::AlertCategory::Device),
               "Full path base-name extraction: Zoom.exe allowed for Device");

    // 1.3: Unlisted process check
    reportTest(!allowlist.isAllowed(L"unknown_spyware.exe", sentinel::core::AlertCategory::Device),
               "Unlisted process is NOT allowed");

    // 1.4: Add OBS with allowAll
    sentinel::core::AllowlistEntry obsEntry{};
    obsEntry.processName = L"obs64.exe";
    obsEntry.allowAll    = true;
    obsEntry.note        = L"Streaming tool";
    allowlist.addOrUpdate(obsEntry);

    reportTest(allowlist.isAllowed(L"obs64.exe", sentinel::core::AlertCategory::Device),
               "obs64.exe allowAll: allowed for Device");
    reportTest(allowlist.isAllowed(L"obs64.exe", sentinel::core::AlertCategory::Clipboard),
               "obs64.exe allowAll: allowed for Clipboard");

    // 1.5: Forward-slash path normalizes to the same base name
    {
        sentinel::core::Allowlist pathList;
        sentinel::core::AllowlistEntry slackEntry{};
        slackEntry.processName = L"slack.exe";
        slackEntry.allowDevice = true;
        pathList.addOrUpdate(slackEntry);

        reportTest(pathList.isAllowed(L"C:/Program Files/Slack/slack.exe",
                                      sentinel::core::AlertCategory::Device),
                   "Forward-slash full path extracts base name");

        // Case-insensitive addOrUpdate must replace, not append a duplicate.
        slackEntry.processName = L"SLACK.EXE";
        slackEntry.allowDevice = false;
        slackEntry.allowClipboard = true;
        pathList.addOrUpdate(slackEntry);

        reportTest(pathList.getEntries().size() == static_cast<std::size_t>(1),
                   "Case-insensitive addOrUpdate replaces existing entry",
                   std::to_string(pathList.getEntries().size()) + " entries");
        reportTest(!pathList.isAllowed(L"slack.exe", sentinel::core::AlertCategory::Device),
                   "Replacement entry carries the updated Device flag");
    }

    // 1.6: Remove entry
    const bool removed = allowlist.remove(L"zoom.exe");
    reportTest(removed, "allowlist.remove(zoom.exe) succeeded");
    reportTest(!allowlist.isAllowed(L"zoom.exe", sentinel::core::AlertCategory::Device),
               "zoom.exe is no longer allowed after removal");

    // -------------------------------------------------------------------------
    // TEST SUITE 2: Allowlist Persistence Cycle
    // -------------------------------------------------------------------------
    std::cout << "\n[Suite 2] Allowlist File Persistence (Save & Load)\n";

    constexpr const char* kTestFilePath = "test_allowlist_temp.txt";

    // Save to disk
    const bool saved = allowlist.saveToFile(kTestFilePath);
    reportTest(saved, "saveToFile succeeded", kTestFilePath);

    // Load from disk into fresh Allowlist instance
    sentinel::core::Allowlist reloadedList;
    const bool loaded = reloadedList.loadFromFile(kTestFilePath);
    reportTest(loaded, "loadFromFile succeeded", kTestFilePath);

    reportTest(reloadedList.isAllowed(L"obs64.exe", sentinel::core::AlertCategory::Device),
               "Reloaded allowlist preserves obs64.exe allowAll");
    reportTest(!reloadedList.isAllowed(L"zoom.exe", sentinel::core::AlertCategory::Device),
               "Reloaded allowlist confirms zoom.exe remains deleted");

    std::remove(kTestFilePath); // Clean up temp file

    // -------------------------------------------------------------------------
    // TEST SUITE 3: DeviceMonitor Lifecycle
    // -------------------------------------------------------------------------
    std::cout << "\n[Suite 3] DeviceMonitor Lifecycle & Scanning\n";

    sentinel::core::EventBus eventBus;
    eventBus.start();

    sentinel::monitors::DeviceMonitor devMonitor(eventBus);

    devMonitor.start();
    reportTest(devMonitor.isRunning(), "DeviceMonitor is running");

    // Let it complete initial scan
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto activeSessions = devMonitor.getActiveSessions();
    reportTest(true, "DeviceMonitor scan completed without crashing",
               std::to_string(activeSessions.size()) + " active sessions");

    devMonitor.stop();
    reportTest(!devMonitor.isRunning(), "DeviceMonitor stopped cleanly and joined thread");

    eventBus.stop();

    // -------------------------------------------------------------------------
    // Final Summary
    // -------------------------------------------------------------------------
    std::cout << "\n========================================================\n";
    if (g_failures == 0) {
        std::cout << "  ALL MILESTONE 4 TESTS PASSED (0 failures)\n";
    } else {
        std::cout << "  VERIFICATION FAILED: " << g_failures << " test(s) failed\n";
    }
    std::cout << "========================================================\n";

    return (g_failures == 0) ? 0 : 1;
}
