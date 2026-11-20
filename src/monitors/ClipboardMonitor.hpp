#pragma once

// ---------------------------------------------------------------------------
// sentinel::monitors::ClipboardMonitor
// Hidden HWND_MESSAGE listener for WM_CLIPBOARDUPDATE with retry handling,
// SecureZeroMemory wiping, and EventBus notification.
// ---------------------------------------------------------------------------

#include "../core/AlertEvent.hpp"
#include "../core/EventBus.hpp"
#include <atomic>
#include <memory>
#include <thread>

namespace sentinel::monitors {

class ClipboardMonitor {
public:
    explicit ClipboardMonitor(sentinel::core::EventBus& eventBus);
    ~ClipboardMonitor();

    // Move-only, not copyable
    ClipboardMonitor(const ClipboardMonitor&)            = delete;
    ClipboardMonitor& operator=(const ClipboardMonitor&) = delete;
    ClipboardMonitor(ClipboardMonitor&&)                 = delete;
    ClipboardMonitor& operator=(ClipboardMonitor&&)      = delete;

    // Start background listener thread with hidden message window
    void start();

    // Signal stop, unregister listener, destroy window, and join thread
    void stop();

    [[nodiscard]] bool isRunning() const noexcept { return isRunning_.load(); }

private:
    void threadWorker(std::stop_token stopToken);

    sentinel::core::EventBus& eventBus_;
    std::atomic<bool>         isRunning_{ false };
    std::jthread              workerThread_;
    // HWND stored as void* so <windows.h> stays out of this header. Atomic
    // because stop() reads it while the worker thread publishes/clears it.
    std::atomic<void*>        hwnd_{ nullptr };
};

} // namespace sentinel::monitors
