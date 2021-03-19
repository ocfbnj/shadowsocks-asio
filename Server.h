#ifndef SERVER_H
#define SERVER_H

#include <cstdint>
#include <string_view>

#include <asio/awaitable.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>

#include "AsyncObject.h"
#include "ChaCha20Poly1305.h"

// Server represents a shadowsocks remote server.
// See https://shadowsocks.org/en/wiki/Protocol.html
class Server {
public:
    Server(std::string_view pwd);
    ~Server() = default;

    asio::awaitable<void> listen(const asio::ip::tcp::endpoint& endpoint);

private:
    asio::awaitable<void> serverSocket(TCPSocket peer);

    std::array<u8, ChaCha20Poly1305<>::KeySize> key;
};

#endif
