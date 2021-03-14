#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/executor.hpp>
#include <asio/use_awaitable.hpp>
#include <spdlog/spdlog.h>

#include "EncryptedConnection.h"
#include "SOCKS5.h"
#include "Server.h"

Server::Server(std::string_view pwd) {
    deriveKey(std::span{(std::uint8_t*)(std::data(pwd)), std::size(pwd)}, key.size(), key);
}

asio::awaitable<void> Server::listen(const asio::ip::tcp::endpoint& endpoint) {
    auto executor = co_await asio::this_coro::executor;

    asio::ip::tcp::acceptor acceptor{executor, endpoint};
    spdlog::info("Listen on {}:{}", endpoint.address().to_string(), endpoint.port());

    while (true) {
        asio::ip::tcp::socket peer = co_await acceptor.async_accept(asio::use_awaitable);
        asio::co_spawn(asio::make_strand(executor), serverSocket(std::move(peer)), asio::detached);
    }
}

asio::awaitable<void> Server::serverSocket(asio::ip::tcp::socket peer) {
    auto executor = co_await asio::this_coro::executor;

    try {
        auto ec = std::make_shared<EncryptedConnection>(std::move(peer), key);
        std::string host, port;
        co_await readTgtAddr(*ec, host, port);

        asio::ip::tcp::resolver r{executor};
        auto results = co_await r.async_resolve(host, port, asio::use_awaitable);
        asio::ip::tcp::endpoint endpoint = *results.begin();
        asio::ip::tcp::socket socket{executor};
        co_await socket.async_connect(endpoint, asio::use_awaitable);
        auto c = std::make_shared<Connection>(std::move(socket));

        asio::co_spawn(executor, ioCopy(c, ec), asio::detached);
        asio::co_spawn(executor, ioCopy(ec, c), asio::detached);
    } catch (const AEAD::DecryptionError& e) {
        spdlog::warn(e.what());
    } catch (const std::system_error& e) {
        if (e.code() != asio::error::eof && e.code() != asio::error::operation_aborted) {
            spdlog::debug(e.what());
        }
    } catch (const std::exception& e) {
        spdlog::debug(e.what());
    }
}
