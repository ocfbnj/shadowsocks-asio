#ifndef SOCKS5_H
#define SOCKS5_H

#include <string>

#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>

#include "Connection.h"
#include "io.h"

// The maximum length of target address (1 + 1 + 255 + 2).
constexpr auto MaxAddrLen = 259;

// SOCKS5 request command defined in RFC 1928 section 4.
enum class CMD {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

// SOCKS5 address type defined in RFC 1928 section 5.
enum class ATYP {
    IPv4 = 0x01,
    DOMAINNAME = 0x03,
    IPv6 = 0x04
};

// Read a SOCK5 address from r.
void readTgtAddr(Reader& r, std::string& host, std::string& port, asio::yield_context yield);

#endif
