// SentinelGuard – src/monitors/ClipboardMonitor.cpp
// Hidden HWND_MESSAGE listener for WM_CLIPBOARDUPDATE with retry handling,
// SecureZeroMemory wiping, and EventBus notification.

#include "ClipboardMonitor.hpp"
#include "PayloadClassifier.hpp"

#include <windows.h>
#include <string>
#include <string_view>
#include <vector>

#include "../core/Win32Utils.hpp"

namespace sentinel::monitors {

namespace {

constexpr wchar_t kWindowClassName[] = L"SentinelGuardClipboardListenerWnd";
constexpr int     kMaxOpenRetries    = 3;
constexpr DWORD   kRetryWaitMs       = 10;

// RAII Scope guard for OpenClipboard / CloseClipboard
class ScopedClipboard {
public:
    explicit ScopedClipboard(HWND hwnd) noexcept
        : isOpen_(::OpenClipboard(hwnd) != FALSE) {}

    ~ScopedClipboard() noexcept
    {
        if (isOpen_) {
            ::CloseClipboard();
        }
    }

    [[nodiscard]] bool isOpen() const noexcept { return isOpen_; }

private:
    bool isOpen_{ false };
};

// RAII Scope guard for GlobalLock / GlobalUnlock
class ScopedGlobalLock {
public:
    explicit ScopedGlobalLock(HGLOBAL hMem) noexcept
        : hMem_(hMem), ptr_(hMem ? ::GlobalLock(hMem) : nullptr) {}

    ~ScopedGlobalLock() noexcept
    {
        if (ptr_ && hMem_) {
            ::GlobalUnlock(hMem_);
        }
    }

    [[nodiscard]] const void* get() const noexcept { return ptr_; }

private:
    HGLOBAL hMem_{ nullptr };
    void*   ptr_{ nullptr };
};

// Open clipboard with contention retries
[[nodiscard]] bool openClipboardWithRetry(HWND hwnd)
{
    for (int i = 0; i < kMaxOpenRetries; ++i) {
        if (::OpenClipboard(hwnd)) {
            return true;
        }
        ::Sleep(kRetryWaitMs);
    }
    return false;
}

} // anonymous namespace

// ── Constructor & Destructor ─────────────────────────────────────────────────
ClipboardMonitor::ClipboardMonitor(sentinel::core::EventBus& eventBus)
    : eventBus_(eventBus)
{}

ClipboardMonitor::~ClipboardMonitor()
{
    stop();
}

void ClipboardMonitor::start()
{
    if (isRunning_.load()) {
        return;
    }
    workerThread_ = std::jthread([this](std::stop_token st) {
        threadWorker(std::move(st));
    });
}

void ClipboardMonitor::stop()
{
    if (workerThread_.joinable()) {
        workerThread_.request_stop();
        if (hwnd_) {
            ::PostMessageW(static_cast<HWND>(hwnd_), WM_CLOSE, 0, 0);
        }
        workerThread_.join();
    }
}

// ── Background Worker Loop ───────────────────────────────────────────────────
void ClipboardMonitor::threadWorker(std::stop_token stopToken)
{
    const HINSTANCE hInst = ::GetModuleHandleW(nullptr);

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc   = ::DefWindowProcW;
    wc.hInstance     = hInst;
    wc.lpszClassName = kWindowClassName;
    ::RegisterClassExW(&wc);

    HWND hwnd = ::CreateWindowExW(
        0, kWindowClassName, L"SentinelGuardClipboardListener",
        0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, hInst, nullptr);

    if (!hwnd) {
        ::UnregisterClassW(kWindowClassName, hInst);
        return;
    }

    if (!::AddClipboardFormatListener(hwnd)) {
        ::DestroyWindow(hwnd);
        ::UnregisterClassW(kWindowClassName, hInst);
        return;
    }

    hwnd_ = hwnd;
    isRunning_.store(true);

    MSG msg{};
    while (!stopToken.stop_requested()) {
        const BOOL bRet = ::GetMessageW(&msg, nullptr, 0, 0);
        if (bRet <= 0 || msg.message == WM_CLOSE || msg.message == WM_QUIT) {
            break;
        }

        if (msg.message == WM_CLIPBOARDUPDATE) {
            // Process clipboard content securely
            if (openClipboardWithRetry(hwnd)) {
                if (::IsClipboardFormatAvailable(CF_UNICODETEXT)) {
                    HANDLE hData = ::GetClipboardData(CF_UNICODETEXT);
                    if (hData) {
                        ScopedGlobalLock memLock(hData);
                        const auto* wText = static_cast<const wchar_t*>(memLock.get());
                        if (wText && *wText != L'\0') {
                            std::wstring wideBuf(wText);
                            const std::size_t charCount = wideBuf.size();
                            std::string  utf8Buf = sentinel::core::wideToUtf8(wideBuf);

                            const ClassificationResult res = classifyPayload(utf8Buf);

                            // Wipe sensitive buffers immediately with SecureZeroMemory
                            ::SecureZeroMemory(wideBuf.data(), wideBuf.size() * sizeof(wchar_t));
                            ::SecureZeroMemory(utf8Buf.data(), utf8Buf.size() * sizeof(char));

                            if (res.isSensitive) {
                                const std::wstring detail =
                                    sentinel::core::utf8ToWide(res.category + ": " +
                                                               res.maskedPreview + " (" +
                                                               res.reason + ")");
                                eventBus_.publish(sentinel::core::AlertEvent::make(
                                    sentinel::core::AlertCategory::Clipboard,
                                    sentinel::core::Severity::Critical,
                                    L"ClipboardMonitor",
                                    detail));
                            } else {
                                const std::wstring detail =
                                    L"Clipboard update: non-sensitive text (" +
                                    std::to_wstring(charCount) + L" chars)";
                                eventBus_.publish(sentinel::core::AlertEvent::make(
                                    sentinel::core::AlertCategory::Clipboard,
                                    sentinel::core::Severity::Info,
                                    L"ClipboardMonitor",
                                    detail));
                            }
                        }
                    }
                }
                ::CloseClipboard();
            }
        }

        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }

    ::RemoveClipboardFormatListener(hwnd);
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(kWindowClassName, hInst);

    hwnd_ = nullptr;
    isRunning_.store(false);
}

} // namespace sentinel::monitors
