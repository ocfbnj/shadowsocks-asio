#include "timer.h"

timer::timer(asio::any_io_executor executor) : inner_timer(executor) {}

bool timer::is_expired() const {
    return err.has_value();
}

void timer::set_timeout(int val, std::function<void()> action) {
    timeout = val;
    timeout_action = std::move(action);

    update();
}

void timer::update() {
    cancel();

    if (timeout > 0) {
        inner_timer.expires_after(std::chrono::seconds(timeout));
        inner_timer.async_wait([this](const std::error_code& error) {
            if (error == asio::error::operation_aborted) {
                return;
            }

            err = error;
            timeout_action();
        });
    }
}

void timer::cancel() {
    std::error_code ignore_rrror;
    inner_timer.cancel(ignore_rrror);

    err.reset();
}
