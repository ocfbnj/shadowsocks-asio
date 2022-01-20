#include <system_error>
#include <utility>

#include <asio/ts/buffer.hpp>

#include "Connection.h"

Connection::Connection(TCPSocket s) : socket(std::move(s)) {}

asio::awaitable<std::size_t> Connection::read(std::span<std::uint8_t> buffer) {
    std::size_t size = co_await socket.async_read_some(asio::buffer(buffer.data(), buffer.size()));
    co_return size;
}

asio::awaitable<std::size_t> Connection::write(std::span<const std::uint8_t> buffer) {
    std::size_t size = co_await asio::async_write(socket, asio::buffer(buffer.data(), buffer.size()));
    co_return size;
}

void Connection::close() {
    if (!closed) {
        closed = true;

        std::error_code ignoreError;
        socket.cancel(ignoreError);
        socket.shutdown(socket.shutdown_send, ignoreError);
    }
}
