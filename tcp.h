#ifndef TCP_H
#define TCP_H

#include <asio/awaitable.hpp>
#include <string_view>

#include "AEAD.h"

asio::awaitable<void> tcpRemote(AEAD::Cipher type, std::string_view remotePort, std::string_view password);

asio::awaitable<void> tcpLocal(AEAD::Cipher type,
                               std::string_view remoteHost, std::string_view remotePort,
                               std::string_view localPort,
                               std::string_view password);

#endif
