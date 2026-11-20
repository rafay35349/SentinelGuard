#pragma once

// ---------------------------------------------------------------------------
// sentinel::monitors::NetworkMonitor
// Polls the IPv4 TCP table (GetExtendedTcpTable / TCP_TABLE_OWNER_PID_ALL),
// resolves owning PIDs to process names, and publishes AlertEvent items when
// new connections appear or a tracked connection changes state.
//
// The owning process name is used as the event source so the Allowlist can
// suppress network alerts by process name, exactly like device events.
// ---------------------------------------------------------------------------

#include "../core/AlertEvent.hpp"
#include "../core/EventBus.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace sentinel::monitors {

// ---------------------------------------------------------------------------
// TcpState – mirrors the MIB_TCP_STATE values so this header stays free of
// <windows.h> and can be included from any translation unit.
// ---------------------------------------------------------------------------
enum class TcpState : uint32_t {
    Closed       = 1,
    Listen       = 2,
    SynSent      = 3,
    SynReceived  = 4,
    Established  = 5,
    FinWait1     = 6,
    FinWait2     = 7,
    CloseWait    = 8,
    Closing      = 9,
    LastAck      = 10,
    TimeWait     = 11,
    DeleteTcb    = 12
};

// ---------------------------------------------------------------------------
// TcpConnection – one parsed row of the owner-PID TCP table.
// Addresses are kept in network byte order exactly as the API reports them.
// ---------------------------------------------------------------------------
struct TcpConnection {
    uint32_t localAddress{ 0 };  // network byte order
    uint32_t remoteAddress{ 0 }; // network byte order
    uint16_t localPort{ 0 };     // host byte order
    uint16_t remotePort{ 0 };    // host byte order
    uint32_t owningPid{ 0 };
    uint32_t state{ 0 };         // TcpState cast to uint32_t
};

// One tracked connection plus the resolved executable name of its owner.
struct ActiveConnection {
    TcpConnection connection;
    std::wstring  processName;
};

// ---------------------------------------------------------------------------
// Formatting / parsing helpers (public for focused unit verification).
// ---------------------------------------------------------------------------

// Formats a network-byte-order IPv4 address as "a.b.c.d".
[[nodiscard]] std::string formatIpv4(uint32_t networkOrderAddress);

// Formats "localIP:localPort -> remoteIP:remotePort (STATE, PID n)".
[[nodiscard]] std::string formatTcpConnection(const TcpConnection& conn);

// Uppercase label for a MIB_TCP_STATE value ("ESTABLISHED", "UNKNOWN", ...).
[[nodiscard]] const char* tcpStateLabel(uint32_t state);

// True for states worth tracking: everything except CLOSED, LISTEN,
// TIME_WAIT and DELETE_TCB (transient teardown / passive sockets).
[[nodiscard]] bool isTrackedTcpState(uint32_t state);

// Parses a raw MIB_TCPTABLE_OWNER_PID block. Bounds-checked against
// byteCount so a truncated buffer cannot be over-read.
[[nodiscard]] std::vector<TcpConnection>
    parseTcpTable(const std::byte* tableBytes, std::size_t byteCount);

// ---------------------------------------------------------------------------
// NetworkMonitor
// ---------------------------------------------------------------------------
class NetworkMonitor {
public:
    explicit NetworkMonitor(sentinel::core::EventBus& eventBus);
    ~NetworkMonitor();

    // Move-only, not copyable
    NetworkMonitor(const NetworkMonitor&)            = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;
    NetworkMonitor(NetworkMonitor&&)                 = delete;
    NetworkMonitor& operator=(NetworkMonitor&&)      = delete;

    // Start background polling thread (no-op if already running)
    void start();

    // Request stop and join worker thread (no-op if already stopped)
    void stop();

    [[nodiscard]] bool isRunning() const noexcept { return isRunning_.load(); }

    // Snapshot of currently tracked active connections
    [[nodiscard]] std::vector<ActiveConnection> getActiveConnections() const;

private:
    using ConnectionKey = std::tuple<uint32_t, uint32_t, uint16_t, uint32_t, uint16_t>;

    void threadWorker(std::stop_token stopToken);

    // Queries the TCP table and resolves owning PIDs to process names.
    // Keyed by connection identity so duplicate rows cannot double-report.
    [[nodiscard]] std::map<ConnectionKey, ActiveConnection> scanActiveConnections();

    // Diffs against the previous snapshot and publishes new/transitioned events.
    void processSnapshot(std::map<ConnectionKey, ActiveConnection> current);

    sentinel::core::EventBus& eventBus_;
    std::atomic<bool>         isRunning_{ false };
    std::jthread              workerThread_;

    mutable std::mutex        mutex_;
    std::condition_variable_any cv_;
    std::map<ConnectionKey, ActiveConnection> previousActive_;
    bool                      firstScanDone_{ false };
};

} // namespace sentinel::monitors
