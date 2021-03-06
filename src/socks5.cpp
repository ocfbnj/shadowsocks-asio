#include <string_view>
#include <unordered_map>

#include "socks5.h"

HandShakeError::HandShakeError(HandShakeErrCode err) : errCode(err) {}

const char* HandShakeError::what() const noexcept {
    static std::unordered_map<HandShakeErrCode, std::string_view> errToStr{
        {HandShakeErrCode::Version, "SOCKS version error"},
        {HandShakeErrCode::Method, "No supported method"},
        {HandShakeErrCode::Command, "No supported command"},
        {HandShakeErrCode::Atyp, "No supported address type"},
    };

    return errToStr[errCode].data();
}
