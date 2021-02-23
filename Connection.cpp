#include <iostream>
#include <utility>

#include "Connection.h"
#include "logger.h"

Connection::Connection(asio::ip::tcp::socket&& s) : socket(std::move(s)) {}

std::size_t Connection::read(asio::mutable_buffer buffer, asio::yield_context yield) {
    return socket.async_read_some(buffer, yield);
}

std::size_t Connection::write(asio::const_buffer buffer, asio::yield_context yield) {
    return asio::async_write(socket, buffer, yield);
}

void Connection::close() {
    std::error_code ignoredErr;
    socket.shutdown(socket.shutdown_send, ignoredErr);
}
