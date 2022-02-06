#include <system_error>
#include <utility>

#include <asio/ts/buffer.hpp>

#include "Connection.h"

Connection::Connection(TcpSocket s) : socket(std::move(s)), timer(socket.get_executor()) {}

asio::awaitable<std::size_t> Connection::read(std::span<std::uint8_t> buffer) {
    updateTimer();

    std::size_t size = 0;

    try {
        size = co_await socket.async_read_some(asio::buffer(buffer.data(), buffer.size()));
    } catch (const std::system_error& e) {
        if (timeout > 0 && timerErr.has_value()) {
            throw std::system_error{asio::error::timed_out, "Read timeout"};
        } else {
            throw std::system_error{e};
        }
    }

    co_return size;
}

asio::awaitable<std::size_t> Connection::write(std::span<const std::uint8_t> buffer) {
    std::size_t size = co_await asio::async_write(socket, asio::buffer(buffer.data(), buffer.size()));
    co_return size;
}

void Connection::close() {
    std::error_code ignoreError;
    socket.shutdown(asio::ip::tcp::socket::shutdown_send, ignoreError);
}

void Connection::setReadTimeout(int val) {
    timeout = val;
    updateTimer();
}

void Connection::updateTimer() {
    std::error_code ignoreError;
    timer.cancel(ignoreError);
    timerErr.reset();

    if (timeout > 0) {
        timer.expires_after(std::chrono::seconds(timeout));
        timer.async_wait([this](const std::error_code& error) {
            if (error != asio::error::operation_aborted) {
                timerErr = error;
                std::error_code ignore;
                socket.cancel(ignore);
            }
        });
    }
}
