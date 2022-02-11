#ifndef TCP_H
#define TCP_H

#include <optional>
#include <string_view>

#include <asio/awaitable.hpp>

#include <crypto/aead/AEAD.h>

asio::awaitable<void> tcpRemote(crypto::AEAD::Method method,
                                std::string_view remoteHost,
                                std::string_view remotePort,
                                std::string_view password);

asio::awaitable<void> tcpLocal(crypto::AEAD::Method method,
                               std::string_view remoteHost,
                               std::string_view remotePort,
                               std::string_view localPort,
                               std::string_view password,
                               std::optional<std::string> aclFilePath);

#endif
