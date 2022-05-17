#ifndef TCP_H
#define TCP_H

#include <asio/awaitable.hpp>

#include "config.h"

asio::awaitable<void> tcp_remote(config conf);
asio::awaitable<void> tcp_local(config conf);

#endif
