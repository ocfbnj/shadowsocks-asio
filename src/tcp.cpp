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

#include "AccessControlList.h"
#include "EncryptedConnection.h"
#include "IpSet.h"
#include "awaitable.h"
#include "io.h"
#include "socks5.h"
#include "tcp.h"

asio::awaitable<void> tcpRemote(crypto::AEAD::Method method,
                                std::string_view remoteHost,
                                std::string_view remotePort,
                                std::string_view password,
                                std::optional<std::string> aclFilePath) {
    auto executor = co_await asio::this_coro::executor;

    // derive a key from password
    std::vector<std::uint8_t> key(crypto::AEAD::keySize(method));
    crypto::deriveKey(std::span{reinterpret_cast<const std::uint8_t*>(password.data()), password.size()}, key);

    // access control list
    AccessControlList acl;
    if (aclFilePath.has_value()) {
        acl = AccessControlList::fromFile(aclFilePath.value());
    }

    // listen
    asio::ip::tcp::endpoint listenEndpoint{asio::ip::make_address(remoteHost), static_cast<std::uint16_t>(std::stoul(remotePort.data()))};
    TcpAcceptor acceptor{executor, listenEndpoint};

    spdlog::info("Listen on {}:{}", listenEndpoint.address().to_string(), listenEndpoint.port());

    auto serveSocket = [&method, &key, &acl](TcpSocket peer) -> asio::awaitable<void> {
        auto executor = co_await asio::this_coro::executor;

        asio::ip::tcp::endpoint peerEndpoint = peer.remote_endpoint();
        std::string peerAddr = fmt::format("{}:{}", peerEndpoint.address().to_string(), peerEndpoint.port());

        if (acl.isBypass(peerEndpoint.address().to_string())) {
            spdlog::debug("Reject client address: {}", peerAddr);
            co_return;
        } else {
            spdlog::debug("Accept client address: {}", peerAddr);
        }

        try {
            // establish an encrypted connection between ss-local and ss-remote
            auto ec = std::make_shared<EncryptedConnection>(std::move(peer), method, key);

            // get target endpoint
            ec->setReadTimeout(120); // 2 minutes
            std::string host, port;
            co_await readTgtAddr(*ec, host, port);
            ec->setReadTimeout(0); // disable read timeout

            spdlog::debug("Target address: {}:{}", host, port);

            // resolve target endpoint
            TcpResolver r{executor};
            TcpResolver::results_type results = co_await r.async_resolve(host, port);
            const asio::ip::tcp::endpoint& endpoint = *results.begin();

            if (acl.isBlockOutbound(endpoint.address().to_string())) {
                spdlog::debug("Block outbound: {}:{}", endpoint.address().to_string(), endpoint.port());
                ec->close();
                co_return;
            } else {
                spdlog::debug("Allow outbound: {}:{}", endpoint.address().to_string(), endpoint.port());
            }

            // connect to target host
            TcpSocket socket{executor};
            co_await socket.async_connect(endpoint);
            auto c = std::make_shared<Connection>(std::move(socket));

            // proxy
            auto strand = asio::make_strand(executor);
            asio::co_spawn(strand, ioCopy(c, ec), asio::detached);
            asio::co_spawn(strand, ioCopy(ec, c), asio::detached);
        } catch (const crypto::AEAD::DecryptionError& e) {
            spdlog::warn("{}: peer {}", e.what(), peerAddr);
        } catch (const EncryptedConnection::DuplicateSalt& e) {
            spdlog::warn("{}: peer {}", e.what(), peerAddr);
        } catch (const std::system_error& e) {
            if (e.code() != asio::error::eof && e.code() != asio::error::timed_out) {
                spdlog::debug("{}: peer {}", e.what(), peerAddr);
            }
        } catch (const std::exception& e) {
            spdlog::warn("{}: peer {}", e.what(), peerAddr);
        }
    };

    while (true) {
        TcpSocket peer = co_await acceptor.async_accept();
        asio::co_spawn(executor, serveSocket(std::move(peer)), asio::detached);
    }
}

asio::awaitable<void> tcpLocal(crypto::AEAD::Method method,
                               std::string_view remoteHost,
                               std::string_view remotePort,
                               std::string_view localPort,
                               std::string_view password,
                               std::optional<std::string> aclFilePath) {
    auto executor = co_await asio::this_coro::executor;

    // derive a key from password
    std::vector<std::uint8_t> key(crypto::AEAD::keySize(method));
    crypto::deriveKey(std::span{reinterpret_cast<const std::uint8_t*>(password.data()), password.size()}, key);

    // access control list
    AccessControlList acl;
    if (aclFilePath.has_value()) {
        acl = AccessControlList::fromFile(aclFilePath.value());
    }

    // resolve ss-remote server endpoint
    TcpResolver resolver{executor};
    TcpResolver::results_type results = co_await resolver.async_resolve(remoteHost.data(), remotePort.data());
    const asio::ip::tcp::endpoint& remoteEndpoint = *results.begin();

    spdlog::debug("Remote server: {}:{}", remoteEndpoint.address().to_string(), remoteEndpoint.port());

    // listen
    asio::ip::tcp::endpoint localEndpoint{asio::ip::tcp::v4(), static_cast<std::uint16_t>(std::stoul(localPort.data()))};
    TcpAcceptor acceptor{executor, localEndpoint};

    spdlog::info("Listen on {}:{}", localEndpoint.address().to_string(), localEndpoint.port());

    auto serveSocket = [&method, &key, &remoteEndpoint, &acl](TcpSocket peer) -> asio::awaitable<void> {
        auto executor = co_await asio::this_coro::executor;

        try {
            // connection between ss-local and client
            auto c = std::make_shared<Connection>(std::move(peer));

            // socks5 handshake
            std::string host, port;
            std::string socks5Addr = co_await handshake(*c, host, port);

            // parse host
            TcpResolver resolver{executor};
            TcpResolver::results_type results = co_await resolver.async_resolve(host, port);
            const asio::ip::tcp::endpoint& targetEndpoint = *results.begin();
            std::string ip = targetEndpoint.address().to_string();

            if (!acl.isBypass(ip)) {
                spdlog::debug("Proxy target address: {}:{}", host, port);

                // connect to ss-remote server
                TcpSocket remoteSocket{executor};
                co_await remoteSocket.async_connect(remoteEndpoint);

                // establish an encrypted connection between ss-local and ss-remote
                auto eC = std::make_shared<EncryptedConnection>(std::move(remoteSocket), method, key);

                // write target address
                co_await eC->write(std::span{reinterpret_cast<const std::uint8_t*>(socks5Addr.data()), socks5Addr.size()});

                // proxy
                auto strand = asio::make_strand(executor);
                asio::co_spawn(strand, ioCopy(c, eC), asio::detached);
                asio::co_spawn(strand, ioCopy(eC, c), asio::detached);
            } else {
                spdlog::debug("Bypass target address: {}:{}", host, port);

                // connect to target host
                TcpSocket targetSocket{executor};
                co_await targetSocket.async_connect(targetEndpoint);

                // establish a normal connection between ss-local and ss-remote
                auto conn = std::make_shared<Connection>(std::move(targetSocket));

                // proxy
                auto strand = asio::make_strand(executor);
                asio::co_spawn(strand, ioCopy(c, conn), asio::detached);
                asio::co_spawn(strand, ioCopy(conn, c), asio::detached);
            }
        } catch (const HandShakeError& e) {
            spdlog::warn("{}", e.what());
        } catch (const std::system_error& e) {
            if (e.code() != asio::error::eof && e.code() != asio::error::timed_out) {
                spdlog::debug("{}", e.what());
            }
        } catch (const std::exception& e) {
            spdlog::warn("{}", e.what());
        }
    };

    while (true) {
        TcpSocket peer = co_await acceptor.async_accept();
        asio::co_spawn(executor, serveSocket(std::move(peer)), asio::detached);
    }
}
