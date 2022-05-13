#ifndef AWAITABLE_H
#define AWAITABLE_H

#include <asio/ts/internet.hpp>
#include <asio/ts/socket.hpp>
#include <asio/use_awaitable.hpp>

using default_token = asio::use_awaitable_t<>;

using tcp_acceptor = default_token::as_default_on_t<asio::ip::tcp::acceptor>;
using tcp_socket = default_token::as_default_on_t<asio::ip::tcp::socket>;
using tcp_resolver = default_token::as_default_on_t<asio::ip::tcp::resolver>;

#endif
