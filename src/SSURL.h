#ifndef SSURL_H
#define SSURL_H

#include <string>

// SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
// userinfo = websafe-base64-encode-utf8(method  ":" password)
// See https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html
struct SSURL {
    struct UserInfo {
        static UserInfo parse(const std::string& str);
        std::string encode() const;

        std::string method;
        std::string password;
    };

    static SSURL parse(const std::string& str);
    std::string encode() const;

    UserInfo userinfo;
    std::string hostname;
    std::string port;
};

#endif
