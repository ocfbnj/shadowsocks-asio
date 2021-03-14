#ifndef CONNECTION_H
#define CONNECTION_H

#include <cstddef>
#include <span>

#include <asio/awaitable.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>

// Connection encapsulates a socket for reading and writing.
class Connection {
public:
    Connection(asio::ip::tcp::socket s);

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<std::uint8_t> buffer);
    void close();

protected:
    asio::ip::tcp::socket socket;

private:
    bool closed = false;
};

#endif
