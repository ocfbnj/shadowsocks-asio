// This file implements ss-local and ss-remote
// See https://shadowsocks.org/en/wiki/Protocol.html

#include <string>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ts/executor.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <crypto/crypto.h>

#include "AsyncObject.h"
#include "EncryptedConnection.h"
#include "io.h"
#include "socks5.h"
#include "tcp.h"

asio::awaitable<void> tcpRemote(crypto::AEAD::Method method, std::string_view remotePort, std::string_view password) {
    auto executor = co_await asio::this_coro::executor;

    // derive a key from password
    std::vector<std::uint8_t> key(crypto::AEAD::keySize(method));
    crypto::deriveKey(std::span{reinterpret_cast<const std::uint8_t*>(password.data()), password.size()}, key);

    // listen
    asio::ip::tcp::endpoint endpoint{asio::ip::tcp::v4(), static_cast<std::uint16_t>(std::stoul(remotePort.data()))};
    Acceptor acceptor{executor, endpoint};

    spdlog::info("Listen on {}:{}", endpoint.address().to_string(), endpoint.port());

    auto serveSocket = [&method, &key](TCPSocket peer) -> asio::awaitable<void> {
        auto executor = co_await asio::this_coro::executor;

        asio::ip::tcp::endpoint endpoint = peer.remote_endpoint();
        std::string peerAddr = fmt::format("{}:{}", endpoint.address().to_string(), endpoint.port());

        try {
            // establish an encrypted connection between ss-local and ss-remote
            auto ec = std::make_shared<EncryptedConnection>(std::move(peer), method, key);

            // get target endpoint
            std::string host, port;
            co_await readTgtAddr(*ec, host, port);
            Resolver r{executor};
            Resolver::results_type results = co_await r.async_resolve(host, port);
            const asio::ip::tcp::endpoint& endpoint = *results.begin();

            // connect to target host
            TCPSocket socket{executor};
            co_await socket.async_connect(endpoint);
            auto c = std::make_shared<Connection>(std::move(socket));

            // proxy
            asio::co_spawn(executor, ioCopy(c, ec), asio::detached);
            asio::co_spawn(executor, ioCopy(ec, c), asio::detached);
        } catch (const crypto::AEAD::DecryptionError& e) {
            spdlog::warn("{}: peer {}", e.what(), peerAddr);
        } catch (const std::system_error& e) {
            if (e.code() != asio::error::eof && e.code() != asio::error::operation_aborted) {
                spdlog::debug(e.what());
            }
        } catch (const std::exception& e) {
            spdlog::warn(e.what());
        }
    };

    while (true) {
        TCPSocket peer = co_await acceptor.async_accept();
        asio::co_spawn(asio::make_strand(executor), serveSocket(std::move(peer)), asio::detached);
    }
}

asio::awaitable<void> tcpLocal(crypto::AEAD::Method method,
                               std::string_view remoteHost, std::string_view remotePort,
                               std::string_view localPort,
                               std::string_view password) {
    auto executor = co_await asio::this_coro::executor;

    // derive a key from password
    std::vector<std::uint8_t> key(crypto::AEAD::keySize(method));
    crypto::deriveKey(std::span{reinterpret_cast<const std::uint8_t*>(password.data()), password.size()}, key);

    // resolve ss-remote server endpoint
    // TODO add timeout
    Resolver resolver{executor};
    Resolver::results_type results = co_await resolver.async_resolve(remoteHost.data(), remotePort.data());
    const asio::ip::tcp::endpoint& remoteEndpoint = *results.begin();

    spdlog::debug("Remote server: {}:{}", remoteEndpoint.address().to_string(), remoteEndpoint.port());

    // listen
    asio::ip::tcp::endpoint localEndpoint{asio::ip::tcp::v4(), static_cast<std::uint16_t>(std::stoul(localPort.data()))};
    Acceptor acceptor{executor, localEndpoint};

    spdlog::info("Listen on {}:{}", localEndpoint.address().to_string(), localEndpoint.port());

    auto serveSocket = [&method, &key, &remoteEndpoint](TCPSocket peer) -> asio::awaitable<void> {
        auto executor = co_await asio::this_coro::executor;

        try {
            // connection between ss-local and client
            auto c = std::make_shared<Connection>(std::move(peer));

            // socks5 handshake
            std::string host, port;
            std::string socks5Addr = co_await handshake(*c, host, port);

            // resolve target endpoint
            Resolver r{executor};
            Resolver::results_type results = co_await r.async_resolve(host, port);
            const asio::ip::tcp::endpoint& targetEndpoint = *results.begin();

            spdlog::debug("Target address: {}:{}", targetEndpoint.address().to_string(), targetEndpoint.port());

            // connect to ss-remote server
            TCPSocket remoteSocket{executor};
            co_await remoteSocket.async_connect(remoteEndpoint);

            // establish an encrypted connection between ss-local and ss-remote
            auto eC = std::make_shared<EncryptedConnection>(std::move(remoteSocket), method, key);

            // write target address
            co_await eC->write(std::span{reinterpret_cast<const std::uint8_t*>(socks5Addr.data()), socks5Addr.size()});

            // proxy
            asio::co_spawn(executor, ioCopy(c, eC), asio::detached);
            asio::co_spawn(executor, ioCopy(eC, c), asio::detached);
        } catch (const HandShakeError& e) {
            spdlog::warn(e.what());
        } catch (const std::system_error& e) {
            if (e.code() != asio::error::eof && e.code() != asio::error::operation_aborted) {
                spdlog::debug(e.what());
            }
        } catch (const std::exception& e) {
            spdlog::warn(e.what());
        }
    };

    while (true) {
        TCPSocket peer = co_await acceptor.async_accept();
        asio::co_spawn(asio::make_strand(executor), serveSocket(std::move(peer)), asio::detached);
    }
}
