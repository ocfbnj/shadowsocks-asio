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
enum class CMD : Byte {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

// SOCKS5 address type defined in RFC 1928 section 5.
enum class Atyp : Byte {
    IPv4 = 0x01,
    DOMAINNAME = 0x03,
    IPv6 = 0x04
};

// SOCKS5 methods defined in RFC 1928 section 3.
enum class Method : Byte {
    NoAuthentication = 0x00,
    GSSAPI = 0x01,
    UsernamePassword = 0x02,
    NoAcceptable = 0xff
};

// SOCKS5 commands defined in RFC 1928 section 4.
enum class Command : Byte {
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
asio::awaitable<std::string> readTgtAddr(Reader auto& r, std::string& host, std::string& port) {
    std::string socks5Addr;

    Byte type;
    co_await readFull(r, BytesView{&type, 1});

    Atyp atyp = static_cast<Atyp>(type);
    socks5Addr.push_back(static_cast<char>(atyp));

    switch (atyp) {
    case Atyp::IPv4: {
        asio::ip::address_v4::bytes_type addr;
        co_await readFull(r, addr);
        host = asio::ip::make_address_v4(addr).to_string();

        socks5Addr.append(reinterpret_cast<const char*>(addr.data()), 4);
    } break;
    case Atyp::DOMAINNAME: {
        Byte len;
        co_await readFull(r, BytesView{&len, 1});

        std::string domainName(len, 0);
        co_await readFull(r, BytesView{reinterpret_cast<Byte*>(domainName.data()), len});
        host = domainName;

        socks5Addr.push_back(static_cast<char>(len));
        socks5Addr.append(std::move(domainName));
    } break;
    case Atyp::IPv6: {
        asio::ip::address_v6::bytes_type addr;
        co_await readFull(r, addr);
        host = asio::ip::make_address_v6(addr).to_string();

        socks5Addr.append(reinterpret_cast<const char*>(addr.data()), 16);
    } break;
    default:
        throw HandShakeError{HandShakeErrCode::Atyp};
    }

    u16 p;
    co_await readFull(r, BytesView{reinterpret_cast<Byte*>(&p), 2});
    socks5Addr.append(reinterpret_cast<const char*>(&p), 2);

    p = ::ntohs(p);
    port = std::to_string(p);

    co_return socks5Addr;
}

asio::awaitable<std::string> handshake(ReadWriter auto& rw, std::string& host, std::string& port) {
    std::array<Byte, MaxMsgLen> buf;

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
    Byte rsp1[] = {Ver, static_cast<Byte>(Method::NoAuthentication)};
    co_await rw.write(BytesView{rsp1});

    // stage 2
    co_await readFull(rw, BytesView{buf.data(), 3});

    if (buf[0] != Ver) {
        throw HandShakeError{HandShakeErrCode::Version};
    }

    if (static_cast<Command>(buf[1]) != Command::Connect) {
        throw HandShakeError{HandShakeErrCode::Command};
    }

    std::string socks5Addr = co_await readTgtAddr(rw, host, port);

    // ok
    Byte rsp2[] = {Ver, 0x00, 0x00, static_cast<Byte>(Atyp::IPv4), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    co_await rw.write(BytesView{rsp2});

    co_return socks5Addr;
}

#endif
