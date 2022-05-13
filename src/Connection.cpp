#include <system_error>
#include <utility>

#include <asio/ts/buffer.hpp>

#include "connection.h"

connection::connection(tcp_socket s) : socket(std::move(s)), timer(socket.get_executor()) {}

asio::awaitable<std::size_t> connection::read(std::span<std::uint8_t> buffer) {
    update_timer();

    std::size_t size = 0;

    try {
        size = co_await socket.async_read_some(asio::buffer(buffer.data(), buffer.size()));
    } catch (const std::system_error& e) {
        if (timeout > 0 && timer_err.has_value()) {
            throw std::system_error{asio::error::timed_out, "Read timeout"};
        } else {
            throw std::system_error{e};
        }
    }

    co_return size;
}

asio::awaitable<std::size_t> connection::write(std::span<const std::uint8_t> buffer) {
    std::size_t size = co_await asio::async_write(socket, asio::buffer(buffer.data(), buffer.size()));
    co_return size;
}

void connection::close() {
    std::error_code ignore_rrror;
    socket.shutdown(asio::ip::tcp::socket::shutdown_send, ignore_rrror);
}

void connection::set_read_timeout(int val) {
    timeout = val;
    update_timer();
}

void connection::update_timer() {
    std::error_code ignore_rrror;
    timer.cancel(ignore_rrror);
    timer_err.reset();

    if (timeout > 0) {
        timer.expires_after(std::chrono::seconds(timeout));
        timer.async_wait([this](const std::error_code& error) {
            if (error != asio::error::operation_aborted) {
                timer_err = error;
                std::error_code ignore;
                socket.cancel(ignore);
            }
        });
    }
}
