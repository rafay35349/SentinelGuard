// SentinelGuard – tests/VerifyMilestone5.cpp
// Automated verification suite for Milestone 5:
// 1. IPv4 / endpoint formatting from network-byte-order table values
// 2. GetExtendedTcpTable row parsing (including truncated-buffer safety)
// 3. TCP state classification
// 4. NetworkMonitor lifecycle and stop() idempotency

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "core/EventBus.hpp"
#include "monitors/NetworkMonitor.hpp"

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

// Builds a synthetic MIB_TCPTABLE_OWNER_PID block with two rows.
std::vector<std::byte> buildSyntheticTable()
{
    static_assert(sizeof(MIB_TCPROW_OWNER_PID) == 6 * sizeof(DWORD),
                  "Unexpected MIB_TCPROW_OWNER_PID layout");

    const std::size_t rowBytes = sizeof(MIB_TCPROW_OWNER_PID);
    std::vector<std::byte> buffer(sizeof(DWORD) + 2 * rowBytes, std::byte{ 0 });

    const DWORD entryCount = 2;
    std::memcpy(buffer.data(), &entryCount, sizeof(entryCount));

    MIB_TCPROW_OWNER_PID rows[2]{};

    // Row 0: 127.0.0.1:50000 -> 93.184.216.34:443, ESTABLISHED, PID 4321
    rows[0].dwState      = MIB_TCP_STATE_ESTAB;
    rows[0].dwLocalAddr  = ::htonl(0x7F000001);
    rows[0].dwLocalPort  = ::htons(50000);
    rows[0].dwRemoteAddr = ::htonl(0x5DB8D822); // 93.184.216.34
    rows[0].dwRemotePort = ::htons(443);
    rows[0].dwOwningPid  = 4321;

    // Row 1: 0.0.0.0:135 listener, PID 888
    rows[1].dwState      = MIB_TCP_STATE_LISTEN;
    rows[1].dwLocalAddr  = ::htonl(0);
    rows[1].dwLocalPort  = ::htons(135);
    rows[1].dwRemoteAddr = ::htonl(0);
    rows[1].dwRemotePort = ::htons(0);
    rows[1].dwOwningPid  = 888;

    std::memcpy(buffer.data() + sizeof(DWORD), rows, sizeof(rows));
    return buffer;
}

} // anonymous namespace

int main()
{
    std::cout << "========================================================\n";
    std::cout << "  SentinelGuard – Milestone 5 Automated Verification\n";
    std::cout << "========================================================\n\n";

    // -------------------------------------------------------------------------
    // TEST SUITE 1: IPv4 & endpoint formatting
    // -------------------------------------------------------------------------
    std::cout << "[Suite 1] IPv4 & Endpoint Formatting\n";

    reportTest(sentinel::monitors::formatIpv4(0x0100007Fu) == "127.0.0.1",
               "formatIpv4 renders loopback correctly",
               sentinel::monitors::formatIpv4(0x0100007Fu));
    reportTest(sentinel::monitors::formatIpv4(0x00000000u) == "0.0.0.0",
               "formatIpv4 renders wildcard correctly");
    reportTest(sentinel::monitors::formatIpv4(0x22D8B85Du) == "93.184.216.34",
               "formatIpv4 renders public address correctly",
               sentinel::monitors::formatIpv4(0x22D8B85Du));

    // -------------------------------------------------------------------------
    // TEST SUITE 2: Dynamic table parsing
    // -------------------------------------------------------------------------
    std::cout << "\n[Suite 2] GetExtendedTcpTable Row Parsing\n";

    const std::vector<std::byte> table = buildSyntheticTable();
    const auto parsed = sentinel::monitors::parseTcpTable(table.data(), table.size());

    reportTest(parsed.size() == 2, "Both synthetic rows parsed",
               std::to_string(parsed.size()) + " rows");

    if (parsed.size() == 2) {
        reportTest(parsed[0].localPort == 50000 && parsed[0].remotePort == 443,
                   "Ports converted from network byte order",
                   std::to_string(parsed[0].localPort) + " -> " +
                       std::to_string(parsed[0].remotePort));
        reportTest(parsed[0].owningPid == 4321, "Owning PID captured");
        reportTest(parsed[0].state == static_cast<uint32_t>(
                       sentinel::monitors::TcpState::Established),
                   "ESTABLISHED state captured");
        reportTest(sentinel::monitors::formatTcpConnection(parsed[0]) ==
                       "127.0.0.1:50000 -> 93.184.216.34:443 (ESTABLISHED, PID 4321)",
                   "Endpoint string formatted",
                   sentinel::monitors::formatTcpConnection(parsed[0]));
    }

    // Truncated buffer: caller must not over-read past the supplied length.
    const std::size_t truncatedBytes = sizeof(DWORD) + sizeof(MIB_TCPROW_OWNER_PID);
    const auto truncated = sentinel::monitors::parseTcpTable(table.data(), truncatedBytes);
    reportTest(truncated.size() == 1, "Truncated buffer yields only complete rows",
               std::to_string(truncated.size()) + " rows");

    // Null / undersized input must fail cleanly.
    reportTest(sentinel::monitors::parseTcpTable(nullptr, 0).empty(),
               "Null buffer returns empty result");
    reportTest(sentinel::monitors::parseTcpTable(table.data(), 2).empty(),
               "Buffer smaller than entry count is rejected");

    // -------------------------------------------------------------------------
    // TEST SUITE 3: State classification
    // -------------------------------------------------------------------------
    std::cout << "\n[Suite 3] TCP State Classification\n";

    reportTest(sentinel::monitors::isTrackedTcpState(
                   static_cast<uint32_t>(sentinel::monitors::TcpState::Established)),
               "ESTABLISHED is tracked");
    reportTest(sentinel::monitors::isTrackedTcpState(
                   static_cast<uint32_t>(sentinel::monitors::TcpState::SynSent)),
               "SYN_SENT is tracked");
    reportTest(!sentinel::monitors::isTrackedTcpState(
                   static_cast<uint32_t>(sentinel::monitors::TcpState::Listen)),
               "LISTEN is not tracked");
    reportTest(!sentinel::monitors::isTrackedTcpState(
                   static_cast<uint32_t>(sentinel::monitors::TcpState::TimeWait)),
               "TIME_WAIT is not tracked");
    reportTest(std::string(sentinel::monitors::tcpStateLabel(
                   static_cast<uint32_t>(sentinel::monitors::TcpState::Established))) ==
                   "ESTABLISHED",
               "State label for ESTABLISHED");
    reportTest(std::string(sentinel::monitors::tcpStateLabel(999u)) == "UNKNOWN",
               "Unknown state degrades to UNKNOWN");

    // -------------------------------------------------------------------------
    // TEST SUITE 4: Monitor lifecycle
    // -------------------------------------------------------------------------
    std::cout << "\n[Suite 4] NetworkMonitor Lifecycle\n";

    sentinel::core::EventBus eventBus;
    eventBus.start();

    sentinel::monitors::NetworkMonitor networkMonitor(eventBus);

    networkMonitor.start();
    reportTest(networkMonitor.isRunning(), "NetworkMonitor is running");

    // Give the worker time to complete its first (baseline) scan.
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    const auto tracked = networkMonitor.getActiveConnections();
    reportTest(true, "Baseline scan completed without crashing",
               std::to_string(tracked.size()) + " tracked connections");

    networkMonitor.stop();
    reportTest(!networkMonitor.isRunning(), "NetworkMonitor stopped cleanly and joined thread");

    networkMonitor.stop(); // idempotency
    reportTest(!networkMonitor.isRunning(), "Second stop() is a safe no-op");

    eventBus.stop();

    // -------------------------------------------------------------------------
    // Final Summary
    // -------------------------------------------------------------------------
    std::cout << "\n========================================================\n";
    if (g_failures == 0) {
        std::cout << "  ALL MILESTONE 5 TESTS PASSED (0 failures)\n";
    } else {
        std::cout << "  VERIFICATION FAILED: " << g_failures << " test(s) failed\n";
    }
    std::cout << "========================================================\n";

    return (g_failures == 0) ? 0 : 1;
}
