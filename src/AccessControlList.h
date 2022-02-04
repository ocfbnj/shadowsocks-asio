#ifndef ACCESS_CONTROL_LIST_H
#define ACCESS_CONTROL_LIST_H

#include <string>

#include "IPSet.h"

class AccessControlList {
public:
    enum Mode {
        WhiteList, // proxies all addresses that didn't match any rules
        BlackList, // bypasses all addresses that didn't match any rules
    };

    static AccessControlList fromFile(const std::string& path);

    bool is_bypass(const std::string& ip) const;

private:
    IPSet bypass_list;
    IPSet proxy_list;

    Mode mode = WhiteList;
};

#endif
