#ifndef SS_URL_H
#define SS_URL_H

#include <string>

// SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
// userinfo = websafe-base64-encode-utf8(method  ":" password)
// See https://shadowsocks.org/en/wiki/SIP002-URI-Scheme.html
struct ss_url {
    friend bool operator==(const ss_url& lhs, const ss_url& rhs) {
        return lhs.userinfo == rhs.userinfo && lhs.hostname == rhs.hostname && lhs.port == rhs.port;
    }

    friend bool operator!=(const ss_url& lhs, const ss_url& rhs) {
        return !(lhs == rhs);
    }

    struct user_info {
        friend bool operator==(const user_info& lhs, const user_info& rhs) {
            return lhs.method == rhs.method && lhs.password == rhs.password;
        }

        friend bool operator!=(const user_info& lhs, const user_info& rhs) {
            return !(lhs == rhs);
        }

        static user_info parse(const std::string& str);
        std::string encode() const;

        std::string method;
        std::string password;
    };

    static ss_url parse(const std::string& str);
    std::string encode() const;

    user_info userinfo;
    std::string hostname;
    std::string port;
};

#endif
