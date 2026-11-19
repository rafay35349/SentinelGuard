#include "EventBus.hpp"

namespace sentinel::core {

// ---------------------------------------------------------------------------
// subscribe – register a handler (must be called before start()).
// ---------------------------------------------------------------------------
void EventBus::subscribe(EventHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_.push_back(std::move(handler));
}

// ---------------------------------------------------------------------------
// publish – enqueue an event and wake the worker.
// ---------------------------------------------------------------------------
void EventBus::publish(AlertEvent event) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(std::move(event));
    }
    cv_.notify_one();
}

// ---------------------------------------------------------------------------
// start – launch the internal worker jthread.
// ---------------------------------------------------------------------------
void EventBus::start() {
    worker_ = std::jthread([this](std::stop_token token) {
        workerLoop(std::move(token));
    });
}

// ---------------------------------------------------------------------------
// stop – request stop, wake the worker, and join.
// ---------------------------------------------------------------------------
void EventBus::stop() {
    if (worker_.joinable()) {
        worker_.request_stop();
        cv_.notify_all();
        worker_.join();
    }
}

// ---------------------------------------------------------------------------
// workerLoop – drain queue and dispatch to handlers.
// ---------------------------------------------------------------------------
void EventBus::workerLoop(std::stop_token token) {
    while (true) {
        std::deque<AlertEvent> batch;

        {
            std::unique_lock<std::mutex> lock(mutex_);
            // Wait until there is work to do, or stop has been requested.
            cv_.wait(lock, token, [this] {
                return !queue_.empty();
            });

            // Drain the entire queue under the lock.
            batch.swap(queue_);
        }

        // Dispatch outside the lock so producers are not blocked.
        for (const AlertEvent& ev : batch) {
            for (const EventHandler& handler : handlers_) {
                handler(ev);
            }
        }

        // If stop was requested and the queue is now empty, exit.
        if (token.stop_requested()) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty()) {
                break;
            }
        }
    }
}

} // namespace sentinel::core
