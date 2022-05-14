#ifndef TCP_H
#define TCP_H

#include <optional>
#include <string_view>

#include <asio/awaitable.hpp>

#include <crypto/aead.h>

#include "config.h"

asio::awaitable<void> tcp_remote(config conf);
asio::awaitable<void> tcp_local(config conf);

#endif
