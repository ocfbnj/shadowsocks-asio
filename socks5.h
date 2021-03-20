#ifndef SOCKS5_H
#define SOCKS5_H

#include <string>
#include <utility>

#include <asio/awaitable.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>

#include "io.h"
#include "type.h"

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
asio::awaitable<void> readTgtAddr(Reader auto& r, std::string& host, std::string& port) {
    u8 type;
    co_await readFull(r, BytesView{&type, 1});

    ATYP atyp = static_cast<ATYP>(type);

    switch (atyp) {
    case ATYP::IPv4: {
        asio::ip::address_v4::bytes_type addr;
        co_await readFull(r, addr);
        host = asio::ip::make_address_v4(addr).to_string();
    } break;
    case ATYP::DOMAINNAME: {
        u8 len;
        co_await readFull(r, BytesView{&len, 1});

        std::string domainName(len, 0);
        co_await readFull(r, BytesView{reinterpret_cast<u8*>(domainName.data()), len});
        host = std::move(domainName);
    } break;
    case ATYP::IPv6: {
        asio::ip::address_v6::bytes_type addr;
        co_await readFull(r, addr);
        host = asio::ip::make_address_v6(addr).to_string();
    } break;
    default:
        co_return;
    }

    u16 p;
    co_await readFull(r, BytesView{reinterpret_cast<u8*>(&p), 2});
    p = ::ntohs(p);
    port = std::to_string(p);
}

#endif
