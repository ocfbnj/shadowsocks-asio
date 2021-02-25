#include <system_error>
#include <utility>

#include <asio/use_awaitable.hpp>

#include "Connection.h"
#include "logger.h"

Connection::Connection(asio::ip::tcp::socket s) : socket(std::move(s)) {}

asio::awaitable<std::size_t> Connection::read(asio::mutable_buffer buffer) {
    std::size_t size = co_await socket.async_read_some(buffer, asio::use_awaitable);
    co_return size;
}

asio::awaitable<std::size_t> Connection::write(asio::const_buffer buffer) {
    std::size_t size = co_await asio::async_write(socket, buffer, asio::use_awaitable);
    co_return size;
}

void Connection::close() {
    std::error_code err;
    socket.cancel(err);
    if (err) {
        log(WARN) << err << '\n';
    }
}
