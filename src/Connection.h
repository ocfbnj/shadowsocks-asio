#ifndef CONNECTION_H
#define CONNECTION_H

#include <cstdint>
#include <optional>
#include <span>

#include <asio/awaitable.hpp>
#include <asio/ts/timer.hpp>

#include "AsyncObject.h"

// Connection encapsulates a socket for reading and writing.
class Connection {
public:
    explicit Connection(TCPSocket s);

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<const std::uint8_t> buffer);

protected:
    TCPSocket socket;

private:
    int timeout = 5; // 5 seconds
    asio::steady_timer timer;
    std::optional<std::error_code> timerErr;
};

#endif
