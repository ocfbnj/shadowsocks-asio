#include <string_view>
#include <unordered_map>

#include "socks5.h"

hand_shake_error::hand_shake_error(hand_shake_err_code err) : errCode(err) {}

const char* hand_shake_error::what() const noexcept {
    static std::unordered_map<hand_shake_err_code, std::string_view> errToStr{
        {hand_shake_err_code::version, "SOCKS version error"},
        {hand_shake_err_code::method, "No supported method"},
        {hand_shake_err_code::command, "No supported command"},
        {hand_shake_err_code::atyp, "No supported address type"},
    };

    return errToStr[errCode].data();
}
