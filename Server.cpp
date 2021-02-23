#include <condition_variable>
#include <functional>

#include <asio/ts/buffer.hpp>

#include "EncryptedConnection.h"
#include "Server.h"
#include "io.h"
#include "logger.h"
#include "socks5.h"

Server::Server(asio::io_context& ctx, const asio::ip::tcp::endpoint& endpoint, const char* pwd)
    : context(ctx), acceptor(ctx, endpoint, true) {
    deriveKey(asio::buffer(pwd, std::strlen(pwd)), key.size(), asio::buffer(key));

    log() << "Listen on " << endpoint << '\n';
}

void Server::doAccept() {
    using namespace std::placeholders;
    acceptor.async_accept(std::bind(&Server::acceptHandler, this, _1, _2));
}

void Server::acceptHandler(const std::error_code& error, asio::ip::tcp::socket peer) {
    if (error) {
        throw std::system_error{error};
    }

    asio::spawn(
        context,
        [s = std::move(peer), this](asio::yield_context yield) mutable {
            auto ec = std::make_shared<EncryptedConnection>(std::move(s), asio::buffer(key));
            try {
                std::string host, port;
                readTgtAddr(*ec, host, port, yield);

                asio::ip::tcp::resolver r{context};
                asio::ip::tcp::endpoint endpoint = *r.async_resolve(host, port, yield).begin();

                asio::ip::tcp::socket socket{context};
                socket.async_connect(endpoint, yield);
                auto c = std::make_shared<Connection>(std::move(socket));

                asio::spawn(context, std::bind(ioCopy, c, ec, std::placeholders::_1));
                asio::spawn(context, std::bind(ioCopy, ec, c, std::placeholders::_1));
            } catch (const std::exception& e) {
                log(WARN) << e.what() << '\n';
            }
        });

    doAccept();
}
