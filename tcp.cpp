#include <array>
#include <string>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ts/executor.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include "AsyncObject.h"
#include "ChaCha20Poly1305.h"
#include "EncryptedConnection.h"
#include "io.h"
#include "socks5.h"
#include "tcp.h"
#include "type.h"

asio::awaitable<void> tcpRemote(std::string_view remotePort, std::string_view password) {
    auto executor = co_await asio::this_coro::executor;

    std::array<u8, ChaCha20Poly1305<>::KeySize> key;
    deriveKey(BytesView{(u8*)(password.data()), password.size()}, key.size(), key);

    asio::ip::tcp::endpoint endpoint{asio::ip::tcp::v4(), static_cast<u16>(std::stoul(remotePort.data()))};
    Acceptor acceptor{executor, endpoint};

    spdlog::info("Listen on {}:{}", endpoint.address().to_string(), endpoint.port());

    auto serverSocket = [&key](TCPSocket peer) -> asio::awaitable<void> {
        auto executor = co_await asio::this_coro::executor;

        asio::ip::tcp::endpoint endpoint = peer.remote_endpoint();
        std::string peerAddr = fmt::format("{}:{}", endpoint.address().to_string(), endpoint.port());

        try {
            auto ec = std::make_shared<EncryptedConnection>(std::move(peer), key);
            std::string host, port;
            co_await readTgtAddr(*ec, host, port);

            Resolver r{executor};
            Resolver::results_type results = co_await r.async_resolve(host, port);
            const asio::ip::tcp::endpoint& endpoint = *results.begin();

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
    };

    while (true) {
        asio::ip::tcp::socket peer = co_await acceptor.async_accept();
        asio::co_spawn(asio::make_strand(executor), serverSocket(std::move(peer)), asio::detached);
    }
}
