// SentinelGuard – src/monitors/NetworkMonitor.cpp
// IPv4 TCP endpoint watcher built on GetExtendedTcpTable + owner-PID rows.
// All table storage is RAII (std::vector<std::byte>); zero manual leaks.

// winsock2.h must precede windows.h (WIN32_LEAN_AND_MEAN keeps winsock.h out).
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include "NetworkMonitor.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

#include "../core/Win32Utils.hpp"
#include "../process/ProcessInspector.hpp"

namespace sentinel::monitors {

namespace {

constexpr std::chrono::milliseconds kPollInterval{ 2000 };
constexpr DWORD                     kInitialTableBytes = 16 * 1024;
constexpr int                       kMaxTableRetries   = 4;

} // anonymous namespace

// ── formatIpv4 ───────────────────────────────────────────────────────────────
std::string formatIpv4(uint32_t networkOrderAddress)
{
    char buf[16]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  static_cast<unsigned>(networkOrderAddress & 0xFFu),
                  static_cast<unsigned>((networkOrderAddress >> 8) & 0xFFu),
                  static_cast<unsigned>((networkOrderAddress >> 16) & 0xFFu),
                  static_cast<unsigned>((networkOrderAddress >> 24) & 0xFFu));
    return std::string(buf);
}

// ── tcpStateLabel ────────────────────────────────────────────────────────────
const char* tcpStateLabel(uint32_t state)
{
    switch (static_cast<TcpState>(state)) {
        case TcpState::Closed:      return "CLOSED";
        case TcpState::Listen:      return "LISTEN";
        case TcpState::SynSent:     return "SYN_SENT";
        case TcpState::SynReceived: return "SYN_RECEIVED";
        case TcpState::Established: return "ESTABLISHED";
        case TcpState::FinWait1:    return "FIN_WAIT1";
        case TcpState::FinWait2:    return "FIN_WAIT2";
        case TcpState::CloseWait:   return "CLOSE_WAIT";
        case TcpState::Closing:     return "CLOSING";
        case TcpState::LastAck:     return "LAST_ACK";
        case TcpState::TimeWait:    return "TIME_WAIT";
        case TcpState::DeleteTcb:   return "DELETE_TCB";
        default:                    return "UNKNOWN";
    }
}

// ── isTrackedTcpState ────────────────────────────────────────────────────────
bool isTrackedTcpState(uint32_t state)
{
    switch (static_cast<TcpState>(state)) {
        case TcpState::Closed:
        case TcpState::Listen:
        case TcpState::TimeWait:
        case TcpState::DeleteTcb:
            return false;
        case TcpState::SynSent:
        case TcpState::SynReceived:
        case TcpState::Established:
        case TcpState::FinWait1:
        case TcpState::FinWait2:
        case TcpState::CloseWait:
        case TcpState::Closing:
        case TcpState::LastAck:
            return true;
        default:
            return false;
    }
}

// ── formatTcpConnection ──────────────────────────────────────────────────────
std::string formatTcpConnection(const TcpConnection& conn)
{
    return formatIpv4(conn.localAddress) + ":" + std::to_string(conn.localPort) +
           " -> " +
           formatIpv4(conn.remoteAddress) + ":" + std::to_string(conn.remotePort) +
           " (" + tcpStateLabel(conn.state) + ", PID " +
           std::to_string(conn.owningPid) + ")";
}

// ── parseTcpTable ────────────────────────────────────────────────────────────
std::vector<TcpConnection> parseTcpTable(const std::byte* tableBytes, std::size_t byteCount)
{
    std::vector<TcpConnection> result;

    if (tableBytes == nullptr || byteCount < sizeof(DWORD)) {
        return result;
    }

    DWORD entryCount = 0;
    std::memcpy(&entryCount, tableBytes, sizeof(entryCount));

    const std::size_t rowBytes  = sizeof(MIB_TCPROW_OWNER_PID);
    const std::size_t available = byteCount - sizeof(DWORD);
    const std::size_t maxRows   = available / rowBytes;
    const std::size_t count     = (std::min)(static_cast<std::size_t>(entryCount), maxRows);

    result.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        MIB_TCPROW_OWNER_PID row{};
        std::memcpy(&row, tableBytes + sizeof(DWORD) + i * rowBytes, rowBytes);

        TcpConnection conn{};
        conn.localAddress  = static_cast<uint32_t>(row.dwLocalAddr);
        conn.remoteAddress = static_cast<uint32_t>(row.dwRemoteAddr);
        conn.localPort     = ::ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
        conn.remotePort    = ::ntohs(static_cast<u_short>(row.dwRemotePort & 0xFFFFu));
        conn.owningPid     = static_cast<uint32_t>(row.dwOwningPid);
        conn.state         = static_cast<uint32_t>(row.dwState);

        result.push_back(conn);
    }

    return result;
}

// ── Constructor & Destructor ─────────────────────────────────────────────────
NetworkMonitor::NetworkMonitor(sentinel::core::EventBus& eventBus)
    : eventBus_(eventBus)
{}

NetworkMonitor::~NetworkMonitor()
{
    stop();
}

// ── Lifecycle ────────────────────────────────────────────────────────────────
void NetworkMonitor::start()
{
    if (isRunning_.load()) {
        return;
    }
    isRunning_.store(true);
    workerThread_ = std::jthread([this](std::stop_token st) {
        threadWorker(std::move(st));
    });
}

void NetworkMonitor::stop()
{
    if (workerThread_.joinable()) {
        workerThread_.request_stop();
        cv_.notify_all();
        workerThread_.join();
    }
    isRunning_.store(false);
}

std::vector<ActiveConnection> NetworkMonitor::getActiveConnections() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ActiveConnection> sessions;
    sessions.reserve(previousActive_.size());
    for (const auto& item : previousActive_) {
        sessions.push_back(item.second);
    }
    return sessions;
}

// ── scanActiveConnections ────────────────────────────────────────────────────
auto NetworkMonitor::scanActiveConnections() -> std::map<ConnectionKey, ActiveConnection>
{
    std::map<ConnectionKey, ActiveConnection> active;

    // Dynamically sized buffer: start at 16 KiB, grow to whatever the API asks
    // for on ERROR_INSUFFICIENT_BUFFER, retry a bounded number of times.
    std::vector<std::byte> buffer(kInitialTableBytes);

    for (int attempt = 0; attempt < kMaxTableRetries; ++attempt) {
        DWORD size = static_cast<DWORD>(buffer.size());

        const DWORD queryResult = ::GetExtendedTcpTable(
            buffer.data(),
            &size,
            FALSE,
            static_cast<ULONG>(AF_INET),
            TCP_TABLE_OWNER_PID_ALL,
            0UL);

        if (queryResult == ERROR_SUCCESS) {
            for (const TcpConnection& conn :
                 parseTcpTable(buffer.data(), static_cast<std::size_t>(size))) {
                // LISTEN/TIME_WAIT rows and the PID-0 system socket carry no
                // actionable owner, so they are not tracked.
                if (!isTrackedTcpState(conn.state) || conn.owningPid == 0) {
                    continue;
                }

                // Fall back to a PID label when inspection fails (protected
                // processes deny PROCESS_QUERY_LIMITED_INFORMATION).
                const auto inspected = sentinel::process::inspectPid(conn.owningPid);

                active.emplace(
                    std::make_tuple(conn.owningPid, conn.localAddress, conn.localPort,
                                    conn.remoteAddress, conn.remotePort),
                    ActiveConnection{
                        conn,
                        inspected.isOk()
                            ? inspected.value().name
                            : (L"PID " + std::to_wstring(conn.owningPid))
                    });
            }
            return active;
        }

        if (queryResult != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            return active;
        }

        buffer.resize(static_cast<std::size_t>(size));
    }

    return active;
}

// ── processSnapshot ──────────────────────────────────────────────────────────
void NetworkMonitor::processSnapshot(std::map<ConnectionKey, ActiveConnection> current)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // The first snapshot is a silent baseline: enumerating every pre-existing
    // connection on launch would flood the dashboard.
    if (!firstScanDone_) {
        firstScanDone_  = true;
        previousActive_ = std::move(current);
        return;
    }

    for (const auto& [key, entry] : current) {
        const auto known = previousActive_.find(key);

        if (known == previousActive_.end()) {
            eventBus_.publish(sentinel::core::AlertEvent::make(
                sentinel::core::AlertCategory::Network,
                sentinel::core::Severity::Warning,
                entry.processName,
                L"New connection: " +
                    sentinel::core::utf8ToWide(formatTcpConnection(entry.connection))));
        } else if (known->second.connection.state != entry.connection.state) {
            eventBus_.publish(sentinel::core::AlertEvent::make(
                sentinel::core::AlertCategory::Network,
                sentinel::core::Severity::Info,
                entry.processName,
                L"State changed: " +
                    sentinel::core::utf8ToWide(formatTcpConnection(entry.connection))));
        }
    }

    previousActive_ = std::move(current);
}

// ── threadWorker ─────────────────────────────────────────────────────────────
void NetworkMonitor::threadWorker(std::stop_token stopToken)
{
    isRunning_.store(true);

    while (!stopToken.stop_requested()) {
        processSnapshot(scanActiveConnections());

        // Interruptible wait
        std::unique_lock<std::mutex> waitLock(mutex_);
        cv_.wait_for(waitLock, stopToken, kPollInterval, [&stopToken] {
            return stopToken.stop_requested();
        });
    }

    isRunning_.store(false);
}

} // namespace sentinel::monitors
