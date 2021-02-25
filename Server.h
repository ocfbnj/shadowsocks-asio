#ifndef SERVER_H
#define SERVER_H

#include <cstdint>

#include <asio/awaitable.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>

#include "ChaCha20Poly1305.h"

// Server represents a shadowsocks remote server.
// See https://shadowsocks.org/en/wiki/Protocol.html
class Server {
public:
    Server(const char* pwd);
    ~Server() = default;

    asio::awaitable<void> listen(const asio::ip::tcp::endpoint& endpoint);

private:
    asio::awaitable<void> serverSocket(asio::ip::tcp::socket peer);

    std::array<std::uint8_t, ChaCha20Poly1305<>::KeySize> key;
};

#endif
