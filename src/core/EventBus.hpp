#pragma once

#include "AlertEvent.hpp"
#include <functional>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <vector>
#include <thread>

namespace sentinel::core {

using EventHandler = std::function<void(const AlertEvent&)>;

// ---------------------------------------------------------------------------
// EventBus – thread-safe multi-producer / single-consumer event bus.
//
// Producers call publish() from any thread.
// A single background jthread drains the queue and dispatches to subscribers.
// ---------------------------------------------------------------------------
class EventBus {
public:
    EventBus()  = default;
    ~EventBus() { stop(); }

    // Not copyable or movable.
    EventBus(const EventBus&)            = delete;
    EventBus& operator=(const EventBus&) = delete;
    EventBus(EventBus&&)                 = delete;
    EventBus& operator=(EventBus&&)      = delete;

    // Push an event onto the queue and wake the worker thread.
    void publish(AlertEvent event);

    // Register a handler to be called on the worker thread.
    void subscribe(EventHandler handler);

    // Start the internal worker thread.
    void start();

    // Request stop, flush remaining events, then join.
    void stop();

private:
    // Worker loop – called on the jthread.
    void workerLoop(std::stop_token token);

    std::deque<AlertEvent>      queue_;
    mutable std::mutex          mutex_;
    std::condition_variable_any cv_;
    std::vector<EventHandler>   handlers_;
    std::jthread                worker_;
};

} // namespace sentinel::core
