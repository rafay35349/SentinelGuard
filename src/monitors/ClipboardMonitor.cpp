// SentinelGuard – src/monitors/ClipboardMonitor.cpp
// Hidden HWND_MESSAGE listener for WM_CLIPBOARDUPDATE with retry handling,
// SecureZeroMemory wiping, and EventBus notification.

#include "ClipboardMonitor.hpp"
#include "PayloadClassifier.hpp"

#include <windows.h>
#include <algorithm>
#include <string>

#include "../core/Win32Utils.hpp"

namespace sentinel::monitors {

namespace {

constexpr wchar_t     kWindowClassName[]     = L"SentinelGuardClipboardListenerWnd";
constexpr int         kMaxOpenRetries        = 3;
constexpr DWORD       kRetryWaitMs           = 10;
constexpr std::size_t kMaxClassifiedChars    = 1'000'000; // 1M UTF-16 units

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

    // Allocation size in bytes; bounds the read of externally owned data.
    [[nodiscard]] std::size_t byteSize() const noexcept
    {
        return (ptr_ != nullptr) ? ::GlobalSize(hMem_) : 0;
    }

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
        if (void* const hwnd = hwnd_.load(); hwnd != nullptr) {
            ::PostMessageW(static_cast<HWND>(hwnd), WM_CLOSE, 0, 0);
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
        ::UnregisterClass(kWindowClassName, hInst);
        return;
    }

    if (!::AddClipboardFormatListener(hwnd)) {
        ::DestroyWindow(hwnd);
        ::UnregisterClass(kWindowClassName, hInst);
        return;
    }

    hwnd_.store(hwnd);
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
                        const std::size_t maxChars = memLock.byteSize() / sizeof(wchar_t);

                        // CF_UNICODETEXT must be NUL-terminated, but the text is
                        // owned by another process: never read past the allocation.
                        if (wText != nullptr && maxChars > 0) {
                            const wchar_t* const terminator =
                                std::find(wText, wText + maxChars, L'\0');
                            const std::size_t charCount =
                                static_cast<std::size_t>(terminator - wText);

                            if (charCount > 0) {
                                std::wstring wideBuf(wText, charCount);

                                if (charCount > kMaxClassifiedChars) {
                                    // Do not copy or classify very large payloads;
                                    // only the size is reported.
                                    ::SecureZeroMemory(wideBuf.data(),
                                                       wideBuf.size() * sizeof(wchar_t));
                                    eventBus_.publish(sentinel::core::AlertEvent::make(
                                        sentinel::core::AlertCategory::Clipboard,
                                        sentinel::core::Severity::Info,
                                        L"ClipboardMonitor",
                                        L"Clipboard update: large text payload (" +
                                            std::to_wstring(charCount) +
                                            L" chars) skipped classification"));
                                } else {
                                    std::string utf8Buf = sentinel::core::wideToUtf8(wideBuf);

                                    const ClassificationResult res = classifyPayload(utf8Buf);

                                    // Wipe sensitive buffers immediately
                                    ::SecureZeroMemory(wideBuf.data(),
                                                       wideBuf.size() * sizeof(wchar_t));
                                    ::SecureZeroMemory(utf8Buf.data(),
                                                       utf8Buf.size() * sizeof(char));

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
    ::UnregisterClass(kWindowClassName, hInst);

    hwnd_.store(nullptr);
    isRunning_.store(false);
}

} // namespace sentinel::monitors
