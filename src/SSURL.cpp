#include <stdexcept>

#include <crypto/codec/base64.h>
#include <crypto/crypto.h>

#include "SSURL.h"

SSURL::UserInfo SSURL::UserInfo::parse(const std::string& str) {
    std::string methodAndPassword = crypto::toString(crypto::codec::base64::decode(crypto::toSpan(str)));
    auto colonPos = methodAndPassword.find(':');

    if (colonPos == std::string::npos) {
        throw std::runtime_error{"Parse SS-URL userinfo failed"};
    }

    return UserInfo{
        .method = methodAndPassword.substr(0, colonPos),
        .password = methodAndPassword.substr(colonPos + 1),
    };
}

std::string SSURL::UserInfo::encode() const {
    return crypto::toString(crypto::codec::base64::encode(crypto::toSpan(method + ":" + password)));
}

SSURL SSURL::parse(const std::string& str) {
    std::string protocol = str.substr(0, 5);
    if (protocol != "ss://") {
        throw std::runtime_error{"The url is not a SS-URL"};
    }

    SSURL ssurl;

    auto atPos = str.find('@', 5);
    if (atPos == std::string::npos) {
        throw std::runtime_error{"Parse SS-URL failed"};
    }
    ssurl.userinfo = UserInfo::parse(str.substr(5, atPos - 5));

    auto colonPos = str.find(':', atPos + 1);
    if (colonPos == std::string::npos) {
        throw std::runtime_error{"Parse SS-URL failed"};
    }
    ssurl.hostname = str.substr(atPos + 1, colonPos - (atPos + 1));

    auto endofPort = str.find_first_of("/?#", colonPos + 1);
    ssurl.port = str.substr(colonPos + 1, endofPort - (colonPos + 1));

    return ssurl;
}

std::string SSURL::encode() const {
    return "ss://" + userinfo.encode() + "@" + hostname + ":" + port;
}
