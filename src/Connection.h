#ifndef CONNECTION_H
#define CONNECTION_H

#include <cstdint>
#include <span>

#include <asio/awaitable.hpp>

#include "AsyncObject.h"

// Connection encapsulates a socket for reading and writing.
class Connection {
public:
    explicit Connection(TCPSocket s);

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<const std::uint8_t> buffer);
    void close();

protected:
    TCPSocket socket;

private:
    bool closed = false;
};

#endif
