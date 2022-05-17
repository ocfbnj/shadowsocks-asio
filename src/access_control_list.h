#ifndef ACCESS_CONTROL_LIST_H
#define ACCESS_CONTROL_LIST_H

#include <string_view>

#include "ip_set.h"
#include "rule_set.h"

class access_control_list {
public:
    enum mode {
        white_list, // proxies all addresses that didn't match any rules
        black_list, // bypasses all addresses that didn't match any rules
    };

    static access_control_list from_file(std::string_view path);

    bool is_bypass(std::string_view ip, std::string_view host = {}) const;
    bool is_block_outbound(std::string_view ip, std::string_view host = {}) const;

private:
    ip_set bypass_list;
    ip_set proxy_list;
    ip_set outbound_block_list;

    rule_set bypass_rules;
    rule_set proxy_rules;
    rule_set outbound_block_rules;

    mode acl_mode = white_list;
};

#endif
