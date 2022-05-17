#include <string_view>
#include <unordered_map>

#include "socks5.h"

namespace socks5 {
handshake_error::handshake_error(handshake_err_code err) : err_code(err) {}

const char* handshake_error::what() const noexcept {
    static std::unordered_map<handshake_err_code, std::string_view> errToStr{
        {handshake_err_code::version, "SOCKS version error"},
        {handshake_err_code::method, "No supported method"},
        {handshake_err_code::command, "No supported command"},
        {handshake_err_code::atyp, "No supported address type"},
    };

    return errToStr[err_code].data();
}
} // namespace socks5
