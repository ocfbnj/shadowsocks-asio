#include <cstdint>

#include "socks5.h"

void readTgtAddr(Reader& r, std::string& host, std::string& port, asio::yield_context yield) {
    std::uint8_t type;
    readFull(r, asio::buffer(&type, 1), yield);

    ATYP atyp = static_cast<ATYP>(type);

    switch (atyp) {
    case ATYP::IPv4: {
        asio::ip::address_v4::bytes_type addr;
        readFull(r, asio::buffer(addr), yield);
        host = asio::ip::make_address_v4(addr).to_string();
    } break;
    case ATYP::DOMAINNAME: {
        std::uint8_t len;
        readFull(r, asio::buffer(&len, 1), yield);

        std::string domainName(len, 0);
        readFull(r, asio::buffer(domainName), yield);
        host = std::move(domainName);
    } break;
    case ATYP::IPv6: {
        asio::ip::address_v6::bytes_type addr;
        readFull(r, asio::buffer(addr), yield);
        host = asio::ip::make_address_v6(addr).to_string();
    } break;
    default:
        return;
    }

    std::uint16_t p;
    readFull(r, asio::buffer(&p, 2), yield);
    p = ntohs(p);
    port = std::to_string(p);
}
