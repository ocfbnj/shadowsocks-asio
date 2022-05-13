#ifndef CONNECTION_H
#define CONNECTION_H

#include <cstdint>
#include <optional>
#include <span>

#include <asio/awaitable.hpp>
#include <asio/ts/timer.hpp>

#include "awaitable.h"

// connection encapsulates a socket for reading and writing.
class connection {
public:
    explicit connection(tcp_socket s);

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<const std::uint8_t> buffer);

    void close();

    void set_read_timeout(int val);

protected:
    tcp_socket socket;

private:
    void update_timer();

    int timeout = 0;
    asio::steady_timer timer;
    std::optional<std::error_code> timer_err;
};

#endif
