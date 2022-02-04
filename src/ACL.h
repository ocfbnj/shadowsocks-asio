#ifndef ACL_H
#define ACL_H

#include <string>

#include "IPSet.h"

class ACL {
public:
    enum Mode {
        WhiteList, // proxies all addresses that didn't match any rules
        BlackList, // bypasses all addresses that didn't match any rules
    };

    static ACL fromFile(const std::string& path);

    bool is_bypass(const std::string& ip) const;

private:
    IPSet bypass_list;
    IPSet proxy_list;

    Mode mode = WhiteList;
};

#endif
