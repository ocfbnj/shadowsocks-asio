#ifndef SSURL_H
#define SSURL_H

#include <string>

// SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
// userinfo = websafe-base64-encode-utf8(method  ":" password)
// See https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html
struct SSURL {
    friend bool operator==(const SSURL& lhs, const SSURL& rhs) {
        return lhs.userinfo == rhs.userinfo && lhs.hostname == rhs.hostname && lhs.port == rhs.port;
    }

    friend bool operator!=(const SSURL& lhs, const SSURL& rhs) {
        return !(lhs == rhs);
    }

    struct UserInfo {
        friend bool operator==(const UserInfo& lhs, const UserInfo& rhs) {
            return lhs.method == rhs.method && lhs.password == rhs.password;
        }

        friend bool operator!=(const UserInfo& lhs, const UserInfo& rhs) {
            return !(lhs == rhs);
        }

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
