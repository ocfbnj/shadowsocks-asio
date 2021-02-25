#ifndef CONNECTION_H
#define CONNECTION_H

#include <cstddef>

#include <asio/awaitable.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>

// Connection encapsulates a socket for reading and writing.
class Connection {
public:
    Connection(asio::ip::tcp::socket s);

    asio::awaitable<std::size_t> read(asio::mutable_buffer buffer);
    asio::awaitable<std::size_t> write(asio::const_buffer buffer);
    void close();

protected:
    asio::ip::tcp::socket socket;
};

#endif
