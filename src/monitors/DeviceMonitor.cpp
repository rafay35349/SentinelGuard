// SentinelGuard – src/monitors/DeviceMonitor.cpp
// Monitors Windows webcam and microphone access transitions using
// CapabilityAccessManager ConsentStore registry state.

#include "DeviceMonitor.hpp"

#include <windows.h>
#include <algorithm>
#include <chrono>

#include "../core/Win32Handle.hpp"

namespace sentinel::monitors {

namespace {

constexpr const wchar_t* kWebcamConsentPath =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam";
constexpr const wchar_t* kMicConsentPath =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone";
constexpr std::chrono::milliseconds kPollInterval{ 1000 };

[[nodiscard]] std::wstring sanitizeAppName(std::wstring_view rawName)
{
    // NonPackaged app names often encode paths with '#' e.g. "C:#Program Files#App#app.exe"
    const auto hashPos = rawName.rfind(L'#');
    if (hashPos != std::wstring_view::npos && hashPos + 1 < rawName.size()) {
        return std::wstring(rawName.substr(hashPos + 1));
    }
    const auto slashPos = rawName.rfind(L'\\');
    if (slashPos != std::wstring_view::npos && slashPos + 1 < rawName.size()) {
        return std::wstring(rawName.substr(slashPos + 1));
    }
    return std::wstring(rawName);
}

[[nodiscard]] bool isAppActivelyUsing(HKEY key)
{
    uint64_t start = 0;
    uint64_t stop  = 0;
    DWORD size = sizeof(uint64_t);

    if (::RegQueryValueExW(key, L"LastUsedTimeStart", nullptr, nullptr,
                           reinterpret_cast<LPBYTE>(&start), &size) != ERROR_SUCCESS) {
        return false;
    }

    size = sizeof(uint64_t);
    if (::RegQueryValueExW(key, L"LastUsedTimeStop", nullptr, nullptr,
                           reinterpret_cast<LPBYTE>(&stop), &size) != ERROR_SUCCESS) {
        stop = 0;
    }

    return (start > 0 && stop == 0) || (start > stop);
}

} // anonymous namespace

// ── Constructor & Destructor ─────────────────────────────────────────────────
DeviceMonitor::DeviceMonitor(sentinel::core::EventBus& eventBus)
    : eventBus_(eventBus)
{}

DeviceMonitor::~DeviceMonitor()
{
    stop();
}

void DeviceMonitor::start()
{
    if (isRunning_.load()) {
        return;
    }
    isRunning_.store(true);
    workerThread_ = std::jthread([this](std::stop_token st) {
        threadWorker(std::move(st));
    });
}

void DeviceMonitor::stop()
{
    if (workerThread_.joinable()) {
        workerThread_.request_stop();
        cv_.notify_all();
        workerThread_.join();
    }
    isRunning_.store(false);
}

std::vector<ActiveDeviceSession> DeviceMonitor::getActiveSessions() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ActiveDeviceSession> sessions;
    sessions.reserve(previousActive_.size());
    for (const auto& item : previousActive_) {
        sessions.push_back(ActiveDeviceSession{ item.first, item.second, 0 });
    }
    return sessions;
}

// ── Registry Scanning Helpers ────────────────────────────────────────────────
void DeviceMonitor::scanCapabilityKey(void* rootHkey, const wchar_t* subKeyPath,
                                      DeviceType dev,
                                      std::set<std::pair<DeviceType, std::wstring>>& activeOut)
{
    sentinel::core::UniqueRegKey rootKey;
    if (::RegOpenKeyExW(static_cast<HKEY>(rootHkey), subKeyPath, 0, KEY_READ, rootKey.put()) != ERROR_SUCCESS) {
        return;
    }

    DWORD index = 0;
    wchar_t subName[512]{};
    DWORD subLen = static_cast<DWORD>(std::size(subName));

    while (::RegEnumKeyExW(rootKey.get(), index++, subName, &subLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        if (_wcsicmp(subName, L"NonPackaged") == 0) {
            // Handle Desktop Win32 applications
            sentinel::core::UniqueRegKey nonPkgKey;
            if (::RegOpenKeyExW(rootKey.get(), L"NonPackaged", 0, KEY_READ, nonPkgKey.put()) == ERROR_SUCCESS) {
                DWORD npIndex = 0;
                wchar_t npSubName[512]{};
                DWORD npSubLen = static_cast<DWORD>(std::size(npSubName));
                while (::RegEnumKeyExW(nonPkgKey.get(), npIndex++, npSubName, &npSubLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                    sentinel::core::UniqueRegKey appKey;
                    if (::RegOpenKeyExW(nonPkgKey.get(), npSubName, 0, KEY_READ, appKey.put()) == ERROR_SUCCESS) {
                        if (isAppActivelyUsing(appKey.get())) {
                            activeOut.insert({ dev, sanitizeAppName(npSubName) });
                        }
                    }
                    npSubLen = static_cast<DWORD>(std::size(npSubName));
                }
            }
        } else {
            // Packaged UWP applications
            sentinel::core::UniqueRegKey appKey;
            if (::RegOpenKeyExW(rootKey.get(), subName, 0, KEY_READ, appKey.put()) == ERROR_SUCCESS) {
                if (isAppActivelyUsing(appKey.get())) {
                    activeOut.insert({ dev, sanitizeAppName(subName) });
                }
            }
        }
        subLen = static_cast<DWORD>(std::size(subName));
    }
}

void DeviceMonitor::scanConsentStore(std::set<std::pair<DeviceType, std::wstring>>& activeOut)
{
    scanCapabilityKey(HKEY_CURRENT_USER, kWebcamConsentPath, DeviceType::Webcam, activeOut);
    scanCapabilityKey(HKEY_CURRENT_USER, kMicConsentPath, DeviceType::Microphone, activeOut);
}

// ── Background Worker Loop ───────────────────────────────────────────────────
void DeviceMonitor::threadWorker(std::stop_token stopToken)
{
    isRunning_.store(true);

    while (!stopToken.stop_requested()) {
        std::set<std::pair<DeviceType, std::wstring>> currentActive;
        scanConsentStore(currentActive);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!firstScanDone_) {
                firstScanDone_ = true;
                // Emit initial detection if an application is already capturing on launch
                for (const auto& item : currentActive) {
                    const std::wstring devName = (item.first == DeviceType::Webcam) ? L"Webcam" : L"Microphone";
                    eventBus_.publish(sentinel::core::AlertEvent::make(
                        sentinel::core::AlertCategory::Device,
                        sentinel::core::Severity::Warning,
                        item.second,
                        L"Active session detected using " + devName));
                }
            } else {
                // Check transitions: Started
                for (const auto& item : currentActive) {
                    if (previousActive_.find(item) == previousActive_.end()) {
                        const std::wstring devName = (item.first == DeviceType::Webcam) ? L"Webcam" : L"Microphone";
                        eventBus_.publish(sentinel::core::AlertEvent::make(
                            sentinel::core::AlertCategory::Device,
                            sentinel::core::Severity::Warning,
                            item.second,
                            L"Started accessing " + devName));
                    }
                }
                // Check transitions: Stopped
                for (const auto& item : previousActive_) {
                    if (currentActive.find(item) == currentActive.end()) {
                        const std::wstring devName = (item.first == DeviceType::Webcam) ? L"Webcam" : L"Microphone";
                        eventBus_.publish(sentinel::core::AlertEvent::make(
                            sentinel::core::AlertCategory::Device,
                            sentinel::core::Severity::Info,
                            item.second,
                            L"Stopped accessing " + devName));
                    }
                }
            }
            previousActive_ = std::move(currentActive);
        }

        // Interruptible wait
        std::unique_lock<std::mutex> waitLock(mutex_);
        cv_.wait_for(waitLock, stopToken, kPollInterval, [&stopToken] {
            return stopToken.stop_requested();
        });
    }

    isRunning_.store(false);
}

} // namespace sentinel::monitors
