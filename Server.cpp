#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/executor.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include "EncryptedConnection.h"
#include "Server.h"
#include "socks5.h"

Server::Server(std::string_view pwd) {
    deriveKey(std::span{(u8*)(std::data(pwd)), std::size(pwd)}, key.size(), key);
}

asio::awaitable<void> Server::listen(const asio::ip::tcp::endpoint& endpoint) {
    auto executor = co_await asio::this_coro::executor;

    asio::ip::tcp::acceptor acceptor{executor, endpoint};
    spdlog::info("Listen on {}:{}", endpoint.address().to_string(), endpoint.port());

    while (true) {
        TCPSocket peer = co_await acceptor.async_accept(asio::use_awaitable);
        asio::co_spawn(asio::make_strand(executor), serverSocket(std::move(peer)), asio::detached);
    }
}

asio::awaitable<void> Server::serverSocket(TCPSocket peer) {
    auto executor = co_await asio::this_coro::executor;

    auto endpoint = peer.remote_endpoint();
    std::string peerAddr = fmt::format("{}:{}", endpoint.address().to_string(), endpoint.port());

    try {
        auto ec = std::make_shared<EncryptedConnection>(std::move(peer), key);
        std::string host, port;
        co_await readTgtAddr(*ec, host, port);

        Resolver r{executor};
        Resolver::results_type results = co_await r.async_resolve(host, port);
        asio::ip::tcp::endpoint endpoint = *results.begin();

        TCPSocket socket{executor};
        co_await socket.async_connect(endpoint);
        auto c = std::make_shared<Connection>(std::move(socket));

        asio::co_spawn(executor, ioCopy(c, ec), asio::detached);
        asio::co_spawn(executor, ioCopy(ec, c), asio::detached);
    } catch (const AEAD::DecryptionError& e) {
        spdlog::warn("{}: peer {}", e.what(), peerAddr);
    } catch (const std::system_error& e) {
        if (e.code() != asio::error::eof && e.code() != asio::error::operation_aborted) {
            spdlog::debug(e.what());
        }
    } catch (const std::exception& e) {
        spdlog::warn(e.what());
    }
}
