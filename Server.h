#ifndef SERVER_H
#define SERVER_H

#include <cstdint>
#include <system_error>

#include <asio/ts/internet.hpp>
#include <asio/ts/io_context.hpp>
#include <asio/ts/socket.hpp>

#include "ChaCha20Poly1305.h"

// Server represents a shadowsocks remote server.
// See https://shadowsocks.org/en/wiki/Protocol.html
class Server {
public:
    Server(asio::io_context& ctx, const asio::ip::tcp::endpoint& endpoint, const char* pwd);
    ~Server() = default;

    void doAccept();

private:
    void acceptHandler(const std::error_code& error, asio::ip::tcp::socket peer);

    asio::io_context& context;
    asio::ip::tcp::acceptor acceptor;

    std::array<std::uint8_t, ChaCha20Poly1305<>::KeySize> key;
};

#endif
