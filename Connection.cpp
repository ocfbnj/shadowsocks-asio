#include <system_error>
#include <utility>

#include <asio/ts/buffer.hpp>
#include <asio/use_awaitable.hpp>

#include "Connection.h"
#include "logger.h"

Connection::Connection(asio::ip::tcp::socket s) : socket(std::move(s)) {}

asio::awaitable<std::size_t> Connection::read(std::span<std::uint8_t> buffer) {
    std::size_t size = co_await socket.async_read_some(
        asio::buffer(std::data(buffer), std::size(buffer)), asio::use_awaitable);
    co_return size;
}

asio::awaitable<std::size_t> Connection::write(std::span<std::uint8_t> buffer) {
    std::size_t size = co_await asio::async_write(
        socket, asio::buffer(std::data(buffer), std::size(buffer)), asio::use_awaitable);
    co_return size;
}

void Connection::close() {
    try {
        socket.cancel();
    } catch (const std::system_error& e) {
        log(WARN) << e.what() << '\n';
    }
}
