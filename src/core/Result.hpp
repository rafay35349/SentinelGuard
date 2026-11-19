#pragma once

// ---------------------------------------------------------------------------
// sentinel::core::Result<T, E>  –  lightweight value-or-error type (C++20).
//
// Mirrors std::expected (C++23) without requiring a newer standard.
// Use the static factories:
//   auto r = Result<Foo>::ok(value);
//   auto r = Result<Foo>::err("something went wrong");
//   if (r.isOk())  use(r.value());
//   else           log(r.error());
//
// Result<void, E> is specialised for operations with no return value.
// ---------------------------------------------------------------------------

#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace sentinel::core {

// ---------------------------------------------------------------------------
// Primary template – T is a real value type.
// ---------------------------------------------------------------------------
template<typename T, typename E = std::string>
class Result {
public:
    [[nodiscard]] static Result ok(T value)
    {
        return Result(std::in_place_index<0>, std::move(value));
    }

    [[nodiscard]] static Result err(E error)
    {
        return Result(std::in_place_index<1>, std::move(error));
    }

    [[nodiscard]] bool isOk()  const noexcept { return storage_.index() == 0; }
    [[nodiscard]] bool isErr() const noexcept { return storage_.index() == 1; }

    // Value accessors – only valid when isOk().
    [[nodiscard]] const T& value()  const&  { return std::get<0>(storage_); }
    [[nodiscard]]       T& value()       &  { return std::get<0>(storage_); }
    [[nodiscard]]       T  value()      &&  { return std::get<0>(std::move(storage_)); }

    // Error accessor – only valid when isErr().
    [[nodiscard]] const E& error() const&   { return std::get<1>(storage_); }
    [[nodiscard]]       E& error()      &   { return std::get<1>(storage_); }

private:
    template<std::size_t I, typename V>
    explicit Result(std::in_place_index_t<I> tag, V&& val)
        : storage_(tag, std::forward<V>(val)) {}

    std::variant<T, E> storage_;
};

// ---------------------------------------------------------------------------
// Specialisation – operations with no return value (like Result<void>).
// ---------------------------------------------------------------------------
template<typename E>
class Result<void, E> {
public:
    [[nodiscard]] static Result ok()          { return Result{true};          }
    [[nodiscard]] static Result err(E error)  { return Result{std::move(error)}; }

    [[nodiscard]] bool isOk()  const noexcept { return !error_.has_value(); }
    [[nodiscard]] bool isErr() const noexcept { return  error_.has_value(); }

    // Error accessor – only valid when isErr().
    [[nodiscard]] const E& error() const { return *error_; }

private:
    explicit Result(bool)    noexcept {}
    explicit Result(E error) : error_(std::move(error)) {}

    std::optional<E> error_;
};

} // namespace sentinel::core
