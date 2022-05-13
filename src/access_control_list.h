#ifndef ACCESS_CONTROL_LIST_H
#define ACCESS_CONTROL_LIST_H

#include <string>

#include "ip_set.h"

class access_control_list {
public:
    enum mode {
        white_list, // proxies all addresses that didn't match any rules
        black_list, // bypasses all addresses that didn't match any rules
    };

    static access_control_list from_file(const std::string& path);

    bool is_bypass(const std::string& ip) const;
    bool is_block_outbound(const std::string& ip) const;

private:
    ip_set bypass_list;
    ip_set proxy_list;
    ip_set outbound_block_list;

    mode acl_mode = white_list;
};

#endif
