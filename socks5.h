#ifndef SOCKS5_H
#define SOCKS5_H

#include <exception>
#include <string>
#include <utility>

#include <asio/awaitable.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>

#include "io.h"
#include "type.h"

// VER is the value of VER field described in RFC 1928.
constexpr auto Ver = 0x05;

// The maximum length of target address (1 + 1 + 255 + 2).
constexpr auto MaxAddrLen = 259;

// The maximum length of request message (3 + MaxAddrLen).
constexpr auto MaxMsgLen = 262;

// SOCKS5 request command defined in RFC 1928 section 4.
enum class CMD {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

// SOCKS5 address type defined in RFC 1928 section 5.
enum class Atyp {
    IPv4 = 0x01,
    DOMAINNAME = 0x03,
    IPv6 = 0x04
};

// SOCKS5 methods defined in RFC 1928 section 3.
enum class Method {
    NoAuthentication = 0x00,
    GSSAPI = 0x01,
    UsernamePassword = 0x02,
    NoAcceptable = 0xff
};

// SOCKS5 commands defined in RFC 1928 section 4.
enum class Command {
    Connect = 0x01,
    Bind = 0x02,
    UDP = 0x03
};

enum class HandShakeErrCode {
    Version,
    Method,
    Command,
    Atyp
};

class HandShakeError : public std::exception {
public:
    HandShakeError(HandShakeErrCode err);

    const char* what() const noexcept override;

private:
    HandShakeErrCode errCode;
};

// Read a SOCK5 address from r.
asio::awaitable<void> readTgtAddr(Reader auto& r, std::string& host, std::string& port) {
    u8 type;
    co_await readFull(r, BytesView{&type, 1});

    Atyp atyp = static_cast<Atyp>(type);

    switch (atyp) {
    case Atyp::IPv4: {
        asio::ip::address_v4::bytes_type addr;
        co_await readFull(r, addr);
        host = asio::ip::make_address_v4(addr).to_string();
    } break;
    case Atyp::DOMAINNAME: {
        u8 len;
        co_await readFull(r, BytesView{&len, 1});

        std::string domainName(len, 0);
        co_await readFull(r, BytesView{reinterpret_cast<u8*>(domainName.data()), len});
        host = std::move(domainName);
    } break;
    case Atyp::IPv6: {
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

asio::awaitable<void> handshake(ReadWriter auto& rw, std::string& host, std::string& port) {
    std::array<u8, MaxMsgLen> buf;

    // stage 1
    Size nRead = co_await readFull(rw, BytesView{buf.data(), 2});

    if (buf[0] != Ver) {
        throw HandShakeError{HandShakeErrCode::Version};
    }

    co_await readFull(rw, BytesView{buf.data() + nRead, buf[1]});

    int i = 2;
    for (; i != 2 + buf[1]; i++) {
        if (static_cast<Method>(buf[i]) == Method::NoAuthentication) {
            break;
        }
    }

    if (i == 2 + buf[1]) {
        throw HandShakeError{HandShakeErrCode::Method};
    }

    // ok
    u8 rsp1[] = {Ver, Method::NoAuthentication};
    co_await rw.write(BytesView{rsp1});

    // stage 2
    co_await readFull(rw, BytesView{buf.data(), 3});

    if (buf[0] != Ver) {
        throw HandShakeError{HandShakeErrCode::Version};
    }

    if (static_cast<Command>(buf[1]) != Command::Connect) {
        throw HandShakeError{HandShakeErrCode::Command};
    }

    co_await readTgtAddr(rw, host, port);

    // ok
    u8 rsp2[] = {Ver, 0x00, 0x00, Atyp::IPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    co_await rw.write(BytesView{rsp2});
}

#endif
