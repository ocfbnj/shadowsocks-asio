#include <stdexcept>

#include <crypto/codec/base64url.h>
#include <crypto/crypto.h>

#include "ss_url.h"

ss_url::user_info ss_url::user_info::parse(const std::string& str) {
    std::string method_and_password = crypto::toString(crypto::codec::experimental::base64url::decode(crypto::toSpan(str)));
    auto colon_pos = method_and_password.find(':');

    if (colon_pos == std::string::npos) {
        throw std::runtime_error{"Parse SS-URL userinfo failed"};
    }

    return user_info{
        .method = method_and_password.substr(0, colon_pos),
        .password = method_and_password.substr(colon_pos + 1),
    };
}

std::string ss_url::user_info::encode() const {
    return crypto::toString(crypto::codec::experimental::base64url::encode(crypto::toSpan(method + ":" + password)));
}

ss_url ss_url::parse(const std::string& str) {
    std::string protocol = str.substr(0, 5);
    if (protocol != "ss://") {
        throw std::runtime_error{"The url is not a SS-URL"};
    }

    ss_url ssurl;

    auto at_pos = str.find('@', 5);
    if (at_pos == std::string::npos) {
        throw std::runtime_error{"Parse SS-URL failed"};
    }
    ssurl.userinfo = user_info::parse(str.substr(5, at_pos - 5));

    auto colon_pos = str.find(':', at_pos + 1);
    if (colon_pos == std::string::npos) {
        throw std::runtime_error{"Parse SS-URL failed"};
    }
    ssurl.hostname = str.substr(at_pos + 1, colon_pos - (at_pos + 1));

    auto endof_port = str.find_first_of("/?#", colon_pos + 1);
    ssurl.port = str.substr(colon_pos + 1, endof_port - (colon_pos + 1));

    return ssurl;
}

std::string ss_url::encode() const {
    return "ss://" + userinfo.encode() + "@" + hostname + ":" + port;
}
