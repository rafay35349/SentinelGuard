#pragma once

#include <string>
#include <chrono>
#include <array>
#include <cstddef>
#include <atomic>
#include <stdexcept>
#include <mutex>
#include <vector>

namespace sentinel::core {

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

enum class AlertCategory : uint8_t {
    Process,
    Clipboard,
    Device,
    Network
};

enum class Severity : uint8_t {
    Info,
    Warning,
    Critical
};

// ---------------------------------------------------------------------------
// AlertEvent
// ---------------------------------------------------------------------------

struct AlertEvent {
    uint64_t                              id;
    std::chrono::system_clock::time_point timestamp;
    AlertCategory                         category;
    Severity                              severity;
    std::wstring                          source;
    std::wstring                          detail;

    // Factory: auto-assigns an incrementing id.
    static AlertEvent make(AlertCategory  cat,
                           Severity       sev,
                           std::wstring   src,
                           std::wstring   det)
    {
        static std::atomic<uint64_t> counter{1};
        AlertEvent ev{};
        ev.id        = counter.fetch_add(1, std::memory_order_relaxed);
        ev.timestamp = std::chrono::system_clock::now();
        ev.category  = cat;
        ev.severity  = sev;
        ev.source    = std::move(src);
        ev.detail    = std::move(det);
        return ev;
    }
};

// ---------------------------------------------------------------------------
// RingBuffer<T, N> – fixed-size, thread-safe circular buffer
// ---------------------------------------------------------------------------

template<typename T, std::size_t N>
class RingBuffer {
    static_assert(N > 0, "RingBuffer size must be > 0");

public:
    RingBuffer() = default;

    // Not copyable or movable (mutex member)
    RingBuffer(const RingBuffer&)            = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;

    // Push an item; overwrites oldest entry when the buffer is full.
    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        buf_[tail_] = std::move(item);
        tail_       = (tail_ + 1) % N;
        if (count_ < N) {
            ++count_;
        } else {
            // Overwrite: advance head to discard oldest.
            head_ = (head_ + 1) % N;
        }
    }

    // Returns a copy of all items in insertion order (oldest first).
    [[nodiscard]] std::vector<T> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<T> result;
        result.reserve(count_);
        for (std::size_t i = 0; i < count_; ++i) {
            result.push_back(buf_[(head_ + i) % N]);
        }
        return result;
    }

    [[nodiscard]] std::size_t size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return count_;
    }

    [[nodiscard]] bool empty() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return count_ == 0;
    }

private:
    mutable std::mutex  mutex_;
    std::array<T, N>    buf_{};
    std::size_t         head_{0};
    std::size_t         tail_{0};
    std::size_t         count_{0};
};

} // namespace sentinel::core
