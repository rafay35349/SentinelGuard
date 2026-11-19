#pragma once

// ---------------------------------------------------------------------------
// sentinel::monitors::DeviceMonitor
// Monitors Windows webcam and microphone access transitions using
// CapabilityAccessManager ConsentStore registry state.
// ---------------------------------------------------------------------------

#include "../core/AlertEvent.hpp"
#include "../core/EventBus.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace sentinel::monitors {

enum class DeviceType : uint8_t {
    Webcam,
    Microphone
};

struct ActiveDeviceSession {
    DeviceType   device{ DeviceType::Webcam };
    std::wstring appName;
    uint64_t     startTime{ 0 };
};

class DeviceMonitor {
public:
    explicit DeviceMonitor(sentinel::core::EventBus& eventBus);
    ~DeviceMonitor();

    // Move-only, not copyable
    DeviceMonitor(const DeviceMonitor&)            = delete;
    DeviceMonitor& operator=(const DeviceMonitor&) = delete;
    DeviceMonitor(DeviceMonitor&&)                 = delete;
    DeviceMonitor& operator=(DeviceMonitor&&)      = delete;

    // Start background monitor thread
    void start();

    // Request stop and join worker thread
    void stop();

    [[nodiscard]] bool isRunning() const noexcept { return isRunning_.load(); }

    // Get current active device sessions
    [[nodiscard]] std::vector<ActiveDeviceSession> getActiveSessions() const;

private:
    void threadWorker(std::stop_token stopToken);
    void scanConsentStore(std::set<std::pair<DeviceType, std::wstring>>& activeOut);
    void scanCapabilityKey(void* rootHkey, const wchar_t* subKeyPath, DeviceType dev,
                           std::set<std::pair<DeviceType, std::wstring>>& activeOut);

    sentinel::core::EventBus& eventBus_;
    std::atomic<bool>         isRunning_{ false };
    std::jthread              workerThread_;

    mutable std::mutex        mutex_;
    std::condition_variable_any cv_;
    std::set<std::pair<DeviceType, std::wstring>> previousActive_;
    bool                      firstScanDone_{ false };
};

} // namespace sentinel::monitors
