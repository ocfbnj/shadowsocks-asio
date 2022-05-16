#include <system_error>
#include <utility>

#include <asio/ts/buffer.hpp>

#include "connection.h"

connection::connection(tcp_socket s)
    : socket(std::move(s)),
      read_timer(socket.get_executor()),
      connection_timer(socket.get_executor()) {}

connection::~connection() {
    // we have to cancel these timers first because they may be referencing the socket
    read_timer.cancel();
    connection_timer.cancel();
}

asio::awaitable<std::size_t> connection::read(std::span<std::uint8_t> buffer) {
    read_timer.update();
    connection_timer.update();

    std::size_t size = 0;

    try {
        size = co_await socket.async_read_some(asio::buffer(buffer.data(), buffer.size()));
    } catch (const std::system_error& e) {
        if (read_timer.is_expired()) {
            throw std::system_error{asio::error::timed_out, "Read timeout"};
        } else if (connection_timer.is_expired()) {
            throw std::system_error{asio::error::timed_out, "Connection timeout"};
        } else {
            throw std::system_error{e};
        }
    }

    co_return size;
}

asio::awaitable<std::size_t> connection::write(std::span<const std::uint8_t> buffer) {
    connection_timer.update();

    std::size_t size = 0;

    try {
        size = co_await asio::async_write(socket, asio::buffer(buffer.data(), buffer.size()));
    } catch (const std::system_error& e) {
        if (connection_timer.is_expired()) {
            throw std::system_error{asio::error::timed_out, "Connection timeout"};
        } else {
            throw std::system_error{e};
        }
    }

    co_return size;
}

void connection::close() {
    std::error_code ignore_error;
    socket.shutdown(asio::ip::tcp::socket::shutdown_send, ignore_error);
}

void connection::set_read_timeout(int val) {
    read_timer.set_timeout(val, [this] {
        std::error_code ignore_error;
        socket.cancel(ignore_error);
    });
}

void connection::set_connection_timeout(int val) {
    connection_timer.set_timeout(val, [this] {
        std::error_code ignore_error;
        socket.cancel(ignore_error);
    });
}

asio::ip::tcp::endpoint connection::local_endpoint() const {
    return socket.local_endpoint();
}

asio::ip::tcp::endpoint connection::remote_endpoint() const {
    return socket.remote_endpoint();
}
