#ifndef TIMER_H
#define TIMER_H

#include <functional>
#include <optional>

#include <asio/ts/io_context.hpp>
#include <asio/ts/timer.hpp>

class timer {
public:
    timer(asio::any_io_executor executor);

    bool is_expired() const;

    void set_timeout(int val, std::function<void()> action);
    void update();
    void cancel();

private:
    int timeout = 0;
    asio::steady_timer inner_timer;
    std::optional<std::error_code> err;

    std::function<void()> timeout_action;
};

#endif
