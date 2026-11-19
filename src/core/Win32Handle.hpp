#pragma once

#include <windows.h>
#include <memory>
#include <functional>

namespace sentinel::core {

// ---------------------------------------------------------------------------
// UniqueHandle – move-only RAII wrapper for Win32 HANDLE
// ---------------------------------------------------------------------------
class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept
        : handle_(h) {}

    ~UniqueHandle() noexcept {
        if (valid()) {
            ::CloseHandle(handle_);
        }
    }

    // Move
    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(other.release()) {}

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            if (valid()) {
                ::CloseHandle(handle_);
            }
            handle_ = other.release();
        }
        return *this;
    }

    // No copy
    UniqueHandle(const UniqueHandle&)            = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

    HANDLE release() noexcept {
        HANDLE h = handle_;
        handle_  = INVALID_HANDLE_VALUE;
        return h;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr;
    }

    explicit operator bool() const noexcept { return valid(); }

private:
    HANDLE handle_;
};

// ---------------------------------------------------------------------------
// UniqueRegKey – move-only RAII wrapper for HKEY
// ---------------------------------------------------------------------------
class UniqueRegKey {
public:
    explicit UniqueRegKey(HKEY key = nullptr) noexcept
        : key_(key) {}

    ~UniqueRegKey() noexcept {
        if (valid()) {
            ::RegCloseKey(key_);
        }
    }

    // Move
    UniqueRegKey(UniqueRegKey&& other) noexcept
        : key_(other.release()) {}

    UniqueRegKey& operator=(UniqueRegKey&& other) noexcept {
        if (this != &other) {
            if (valid()) {
                ::RegCloseKey(key_);
            }
            key_ = other.release();
        }
        return *this;
    }

    // No copy
    UniqueRegKey(const UniqueRegKey&)            = delete;
    UniqueRegKey& operator=(const UniqueRegKey&) = delete;

    [[nodiscard]] HKEY get() const noexcept { return key_; }

    HKEY release() noexcept {
        HKEY k = key_;
        key_   = nullptr;
        return k;
    }

    [[nodiscard]] bool valid() const noexcept { return key_ != nullptr; }

    explicit operator bool() const noexcept { return valid(); }

private:
    HKEY key_;
};

} // namespace sentinel::core
