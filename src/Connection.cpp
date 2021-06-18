#include <system_error>
#include <utility>

// TODO we don't need `asio::use_awaitable`
#include <asio/use_awaitable.hpp>

#include <asio/ts/buffer.hpp>

#include "Connection.h"

Connection::Connection(TCPSocket s) : socket(std::move(s)) {}

asio::awaitable<Size> Connection::read(BytesView buffer) {
    Size size = co_await socket.async_read_some(asio::buffer(buffer.data(), buffer.size()), asio::use_awaitable);
    co_return size;
}

asio::awaitable<Size> Connection::write(BytesView buffer) {
    Size size = co_await asio::async_write(socket, asio::buffer(buffer.data(), buffer.size()), asio::use_awaitable);
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
