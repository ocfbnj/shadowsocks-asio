#ifndef ACCESS_CONTROL_LIST_H
#define ACCESS_CONTROL_LIST_H

#include <string>

#include "IpSet.h"

class AccessControlList {
public:
    enum Mode {
        WhiteList, // proxies all addresses that didn't match any rules
        BlackList, // bypasses all addresses that didn't match any rules
    };

    static AccessControlList fromFile(const std::string& path);

    bool isBypass(const std::string& ip) const;

private:
    IpSet bypassList;
    IpSet proxyList;

    Mode mode = WhiteList;
};

#endif
