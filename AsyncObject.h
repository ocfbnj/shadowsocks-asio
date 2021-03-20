#ifndef ASYNC_OBJECT_H
#define ASYNC_OBJECT_H

#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>
#include <asio/use_awaitable.hpp>

using DefaultToken = asio::use_awaitable_t<>;

using Acceptor = DefaultToken::as_default_on_t<asio::ip::tcp::acceptor>;
using TCPSocket = DefaultToken::as_default_on_t<asio::ip::tcp::socket>;
using Resolver = DefaultToken::as_default_on_t<asio::ip::tcp::resolver>;

#endif
