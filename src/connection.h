#ifndef CONNECTION_H
#define CONNECTION_H

#include <cstdint>
#include <optional>
#include <span>

#include <asio/awaitable.hpp>
#include <asio/ts/timer.hpp>

#include "awaitable.h"
#include "timer.h"

// connection encapsulates a socket for reading and writing.
class connection {
public:
    explicit connection(tcp_socket s);
    ~connection();

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<const std::uint8_t> buffer);

    void close();

    void set_read_timeout(int val);
    void set_connection_timeout(int val);

protected:
    tcp_socket socket;

private:
    timer read_timer;
    timer connection_timer;
};

#endif
