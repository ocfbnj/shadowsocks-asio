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

#include "access_control_list.h"
#include "awaitable.h"
#include "convert.h"
#include "encrypted_connection.h"
#include "io.h"
#include "ip_set.h"
#include "socks5.h"
#include "tcp.h"

asio::awaitable<void> tcp_remote(config conf) {
    auto executor = co_await asio::this_coro::executor;
    auto method = *method_from_string(conf.method);

    // derive a key from password
    std::vector<std::uint8_t> key(crypto::aead::key_size(method));
    crypto::derive_key(std::span{reinterpret_cast<const std::uint8_t*>(conf.password.data()), conf.password.size()}, key);

    // access control list
    access_control_list acl;
    if (conf.acl_file_path) {
        acl = access_control_list::from_file(*conf.acl_file_path);
    }

    // listen
    asio::ip::tcp::endpoint listen_endpoint{asio::ip::make_address(conf.remote_host), static_cast<std::uint16_t>(std::stoul(conf.remote_port.data()))};
    tcp_acceptor acceptor{executor, listen_endpoint};

    spdlog::info("Listen on {}:{}", listen_endpoint.address().to_string(), listen_endpoint.port());

    auto serve_socket = [&method, &key, &acl](tcp_socket peer) -> asio::awaitable<void> {
        auto executor = co_await asio::this_coro::executor;

        asio::ip::tcp::endpoint peer_endpoint = peer.remote_endpoint();
        std::string peer_addr = fmt::format("{}:{}", peer_endpoint.address().to_string(), peer_endpoint.port());

        if (acl.is_bypass(peer_endpoint.address().to_string())) {
            spdlog::debug("Reject client address: {}", peer_addr);
            co_return;
        } else {
            spdlog::debug("Accept client address: {}", peer_addr);
        }

        try {
            // establish an encrypted connection between ss-local and ss-remote
            auto ec = std::make_shared<encrypted_connection>(std::move(peer), method, key);

            // get target endpoint
            ec->set_read_timeout(120); // 2 minutes
            std::string host, port;
            co_await socks5::read_tgt_addr(*ec, host, port);
            ec->set_read_timeout(0); // disable read timeout

            spdlog::debug("Target address: {}:{}", host, port);

            // resolve target endpoint
            tcp_resolver r{executor};
            tcp_resolver::results_type results = co_await r.async_resolve(host, port);
            const asio::ip::tcp::endpoint& endpoint = *results.begin();

            if (acl.is_block_outbound(endpoint.address().to_string())) {
                spdlog::debug("Block outbound: {}:{}", endpoint.address().to_string(), endpoint.port());
                ec->close();
                co_return;
            } else {
                spdlog::debug("Allow outbound: {}:{}", endpoint.address().to_string(), endpoint.port());
            }

            // connect to target host
            tcp_socket socket{executor};
            co_await socket.async_connect(endpoint);
            auto c = std::make_shared<connection>(std::move(socket));

            // proxy
            auto strand = asio::make_strand(executor);
            asio::co_spawn(strand, io_copy(c, ec), asio::detached);
            asio::co_spawn(strand, io_copy(ec, c), asio::detached);
        } catch (const crypto::aead::decryption_error& e) {
            spdlog::warn("{}: peer {}", e.what(), peer_addr);
        } catch (const encrypted_connection::duplicate_salt& e) {
            spdlog::warn("{}: peer {}", e.what(), peer_addr);
        } catch (const std::system_error& e) {
            if (e.code() != asio::error::eof && e.code() != asio::error::timed_out) {
                spdlog::debug("{}: peer {}", e.what(), peer_addr);
            }
        } catch (const std::exception& e) {
            spdlog::warn("{}: peer {}", e.what(), peer_addr);
        }
    };

    while (true) {
        try {
            tcp_socket peer = co_await acceptor.async_accept();
            asio::co_spawn(executor, serve_socket(std::move(peer)), asio::detached);
        } catch (const std::exception& e) {
            spdlog::warn("Accept error: {}", e.what());
        }
    }
}

asio::awaitable<void> tcp_local(config conf) {
    auto executor = co_await asio::this_coro::executor;
    auto method = *method_from_string(conf.method);

    // derive a key from password
    std::vector<std::uint8_t> key(crypto::aead::key_size(method));
    crypto::derive_key(std::span{reinterpret_cast<const std::uint8_t*>(conf.password.data()), conf.password.size()}, key);

    // access control list
    access_control_list acl;
    if (conf.acl_file_path) {
        acl = access_control_list::from_file(*conf.acl_file_path);
    }

    // resolve ss-remote server endpoint
    tcp_resolver resolver{executor};
    tcp_resolver::results_type results = co_await resolver.async_resolve(conf.remote_host.data(), conf.remote_port.data());
    const asio::ip::tcp::endpoint& remote_endpoint = *results.begin();

    spdlog::debug("Remote server: {}:{}", remote_endpoint.address().to_string(), remote_endpoint.port());

    // listen
    asio::ip::tcp::endpoint local_endpoint{asio::ip::tcp::v4(), static_cast<std::uint16_t>(std::stoul(conf.local_port.data()))};
    tcp_acceptor acceptor{executor, local_endpoint};

    spdlog::info("Listen on {}:{}", local_endpoint.address().to_string(), local_endpoint.port());

    auto serve_socket = [&method, &key, &remote_endpoint, &acl](tcp_socket peer) -> asio::awaitable<void> {
        auto executor = co_await asio::this_coro::executor;

        try {
            // connection between ss-local and client
            auto c = std::make_shared<connection>(std::move(peer));

            // socks5 handshake
            std::string host, port;
            std::string socks5_addr = co_await socks5::handshake(*c, host, port);

            // parse host
            tcp_resolver resolver{executor};
            tcp_resolver::results_type results = co_await resolver.async_resolve(host, port);
            const asio::ip::tcp::endpoint& target_endpoint = *results.begin();
            std::string ip = target_endpoint.address().to_string();

            if (!acl.is_bypass(ip)) {
                spdlog::debug("Proxy target address: {}:{} ({})", host, port, ip);

                // connect to ss-remote server
                tcp_socket remote_socket{executor};
                co_await remote_socket.async_connect(remote_endpoint);

                // establish an encrypted connection between ss-local and ss-remote
                auto ec = std::make_shared<encrypted_connection>(std::move(remote_socket), method, key);

                // write target address
                co_await ec->write(std::span{reinterpret_cast<const std::uint8_t*>(socks5_addr.data()), socks5_addr.size()});

                // proxy
                auto strand = asio::make_strand(executor);
                asio::co_spawn(strand, io_copy(c, ec), asio::detached);
                asio::co_spawn(strand, io_copy(ec, c), asio::detached);
            } else {
                spdlog::debug("Bypass target address: {}:{} ({})", host, port, ip);

                // connect to target host
                tcp_socket target_socket{executor};
                co_await target_socket.async_connect(target_endpoint);

                // establish a normal connection between ss-local and target host
                auto conn = std::make_shared<connection>(std::move(target_socket));

                // proxy
                auto strand = asio::make_strand(executor);
                asio::co_spawn(strand, io_copy(c, conn), asio::detached);
                asio::co_spawn(strand, io_copy(conn, c), asio::detached);
            }
        } catch (const socks5::handshake_error& e) {
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
        try {
            tcp_socket peer = co_await acceptor.async_accept();
            asio::co_spawn(executor, serve_socket(std::move(peer)), asio::detached);
        } catch (const std::exception& e) {
            spdlog::warn("Accept error: {}", e.what());
        }
    }
}
