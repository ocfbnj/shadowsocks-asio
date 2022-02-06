#ifndef AWAITABLE_H
#define AWAITABLE_H

#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>
#include <asio/use_awaitable.hpp>

using DefaultToken = asio::use_awaitable_t<>;

using TcpAcceptor = DefaultToken::as_default_on_t<asio::ip::tcp::acceptor>;
using TcpSocket = DefaultToken::as_default_on_t<asio::ip::tcp::socket>;
using TcpResolver = DefaultToken::as_default_on_t<asio::ip::tcp::resolver>;

#endif
