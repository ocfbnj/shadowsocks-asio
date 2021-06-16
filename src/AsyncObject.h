#ifndef ASYNC_OBJECT_H
#define ASYNC_OBJECT_H

#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>
#include <asio/use_awaitable.hpp>

#ifdef WIN32
using Acceptor = asio::ip::tcp::acceptor;
using TCPSocket = asio::ip::tcp::socket;
using Resolver = asio::ip::tcp::resolver;
#else
using DefaultToken = asio::use_awaitable_t<>;

using Acceptor = DefaultToken::as_default_on_t<asio::ip::tcp::acceptor>;
using TCPSocket = DefaultToken::as_default_on_t<asio::ip::tcp::socket>;
using Resolver = DefaultToken::as_default_on_t<asio::ip::tcp::resolver>;
#endif

#endif
