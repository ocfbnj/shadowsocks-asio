#ifndef TCP_H
#define TCP_H

#include <asio/awaitable.hpp>
#include <string_view>

asio::awaitable<void> tcpRemote(std::string_view remotePort, std::string_view password);

asio::awaitable<void> tcpLocal(std::string_view remoteHost, std::string_view remotePort,
                               std::string_view localPort,
                               std::string_view password);

#endif
