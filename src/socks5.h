#ifndef SOCKS5_H
#define SOCKS5_H

#include <exception>
#include <string>
#include <utility>

#include <asio/awaitable.hpp>
#include <asio/ts/internet.hpp>

#include "io.h"

// ver is the value of VER field described in RFC 1928.
constexpr auto ver = 0x05;

// The maximum length of target address (1 + 1 + 255 + 2).
constexpr auto max_addr_len = 259;

// The maximum length of request message (3 + max_addr_len).
constexpr auto max_msg_len = 262;

// SOCKS5 request command defined in RFC 1928 section 4.
enum class cmd : std::uint8_t {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03
};

// SOCKS5 address type defined in RFC 1928 section 5.
enum class atyp : std::uint8_t {
    ipv4 = 0x01,
    domainname = 0x03,
    ipv6 = 0x04
};

// SOCKS5 methods defined in RFC 1928 section 3.
enum class method : std::uint8_t {
    no_authentication = 0x00,
    gssapi = 0x01,
    username_password = 0x02,
    no_acceptable = 0xff
};

// SOCKS5 commands defined in RFC 1928 section 4.
enum class command : std::uint8_t {
    connect = 0x01,
    bind = 0x02,
    udp = 0x03
};

enum class hand_shake_err_code {
    version,
    method,
    command,
    atyp
};

class hand_shake_error : public std::exception {
public:
    hand_shake_error(hand_shake_err_code err);

    const char* what() const noexcept override;

private:
    hand_shake_err_code err_code;
};

// Read a SOCK5 address from r.
asio::awaitable<std::string> read_tgt_addr(reader auto& r, std::string& host, std::string& port) {
    std::string socks5_addr;

    std::uint8_t type;
    co_await read_full(r, std::span{&type, 1});

    atyp at = static_cast<atyp>(type);
    socks5_addr.push_back(static_cast<char>(at));

    switch (at) {
    case atyp::ipv4: {
        asio::ip::address_v4::bytes_type addr;
        co_await read_full(r, addr);
        host = asio::ip::make_address_v4(addr).to_string();

        socks5_addr.append(reinterpret_cast<const char*>(addr.data()), 4);
    } break;
    case atyp::domainname: {
        std::uint8_t len;
        co_await read_full(r, std::span{&len, 1});

        std::string domain_name(len, 0);
        co_await read_full(r, std::span{reinterpret_cast<std::uint8_t*>(domain_name.data()), len});
        host = domain_name;

        socks5_addr.push_back(static_cast<char>(len));
        socks5_addr.append(domain_name);
    } break;
    case atyp::ipv6: {
        asio::ip::address_v6::bytes_type addr;
        co_await read_full(r, addr);
        host = asio::ip::make_address_v6(addr).to_string();

        socks5_addr.append(reinterpret_cast<const char*>(addr.data()), 16);
    } break;
    default:
        throw hand_shake_error{hand_shake_err_code::atyp};
    }

    std::uint16_t p;
    co_await read_full(r, std::span{reinterpret_cast<std::uint8_t*>(&p), 2});
    socks5_addr.append(reinterpret_cast<const char*>(&p), 2);

    p = ntohs(p);
    port = std::to_string(p);

    co_return socks5_addr;
}

asio::awaitable<std::string> handshake(reader_writer auto& rw, std::string& host, std::string& port) {
    std::array<std::uint8_t, max_msg_len> buf;

    // stage 1
    std::size_t n_read = co_await read_full(rw, std::span{buf.data(), 2});

    if (buf[0] != ver) {
        throw hand_shake_error{hand_shake_err_code::version};
    }

    co_await read_full(rw, std::span{buf.data() + n_read, buf[1]});

    int i = 2;
    for (; i != 2 + buf[1]; i++) {
        if (static_cast<method>(buf[i]) == method::no_authentication) {
            break;
        }
    }

    if (i == 2 + buf[1]) {
        throw hand_shake_error{hand_shake_err_code::method};
    }

    // ok
    std::uint8_t rsp1[] = {ver, static_cast<std::uint8_t>(method::no_authentication)};
    co_await rw.write(std::span{rsp1});

    // stage 2
    co_await read_full(rw, std::span{buf.data(), 3});

    if (buf[0] != ver) {
        throw hand_shake_error{hand_shake_err_code::version};
    }

    if (static_cast<command>(buf[1]) != command::connect) {
        throw hand_shake_error{hand_shake_err_code::command};
    }

    std::string socks5_addr = co_await read_tgt_addr(rw, host, port);

    // ok
    std::uint8_t rsp2[] = {ver, 0x00, 0x00, static_cast<std::uint8_t>(atyp::ipv4), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    co_await rw.write(std::span{rsp2});

    co_return socks5_addr;
}

#endif
