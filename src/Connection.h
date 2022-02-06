#ifndef CONNECTION_H
#define CONNECTION_H

#include <cstdint>
#include <optional>
#include <span>

#include <asio/awaitable.hpp>
#include <asio/ts/timer.hpp>

#include "awaitable.h"

// Connection encapsulates a socket for reading and writing.
class Connection {
public:
    explicit Connection(TcpSocket s);

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<const std::uint8_t> buffer);

    void close();

    void setReadTimeout(int val);

protected:
    TcpSocket socket;

private:
    void updateTimer();

    int timeout = 0;
    asio::steady_timer timer;
    std::optional<std::error_code> timerErr;
};

#endif
