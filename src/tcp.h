#ifndef TCP_H
#define TCP_H

#include <optional>
#include <string_view>

#include <asio/awaitable.hpp>

#include <crypto/aead/AEAD.h>

asio::awaitable<void> tcp_remote(crypto::AEAD::Method method,
                                 std::string_view remote_host,
                                 std::string_view remote_port,
                                 std::string_view password,
                                 std::optional<std::string> acl_file_path);

asio::awaitable<void> tcp_local(crypto::AEAD::Method method,
                                std::string_view remoteHost,
                                std::string_view remote_port,
                                std::string_view local_port,
                                std::string_view password,
                                std::optional<std::string> acl_file_path);

#endif
