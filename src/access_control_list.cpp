#include <cctype>
#include <fstream>
#include <stdexcept>

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include "access_control_list.h"

namespace {
void trim_comment(std::string& str) {
    str.erase(std::find(str.begin(), str.end(), '#'), str.end());
}

void trim_space(std::string& str) {
    str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](char c) { return !std::isspace(c); }));
    str.erase(std::find_if(str.rbegin(), str.rend(), [](char c) { return !std::isspace(c); }).base(), str.end());
}
} // namespace

access_control_list access_control_list::from_file(std::string_view path) {
    access_control_list acl;

    std::ifstream ifs{path.data(), std::ifstream::in | std::ifstream::binary};
    if (!ifs) {
        throw std::runtime_error{fmt::format("Cannot open acl file: {}", path)};
    }

    ip_set* cur_list = &acl.bypass_list;
    rule_set* cur_rule_set = &acl.bypass_rules;

    std::string line;
    while (std::getline(ifs, line)) {
        trim_comment(line);
        trim_space(line);

        if (line.empty()) {
            continue;
        }

        if (line == "[proxy_all]" || line == "[accept_all]") {
            acl.acl_mode = white_list;
        } else if (line == "[bypass_all]" || line == "[reject_all]") {
            acl.acl_mode = black_list;
        } else if (line == "[bypass_list]" || line == "[black_list]") {
            cur_list = &acl.bypass_list;
            cur_rule_set = &acl.bypass_rules;
        } else if (line == "[proxy_list]" || line == "[white_list]") {
            cur_list = &acl.proxy_list;
            cur_rule_set = &acl.proxy_rules;
        } else if (line == "[outbound_block_list]") {
            cur_list = &acl.outbound_block_list;
            cur_rule_set = &acl.outbound_block_rules;
        } else {
            if (!cur_list->insert(line)) {
                if (!cur_rule_set->insert(line)) {
                    spdlog::warn("Couldn't insert to ip set and rule set: {}", line);
                } else {
                    spdlog::trace("Add to rule set: {}", line);
                }
            } else {
                spdlog::trace("Add to ip set: {}", line);
            }
        }
    }

    return acl;
}

bool access_control_list::is_bypass(std::string_view ip, std::string_view host) const {
    if (bypass_list.contains(ip)) {
        return true;
    }

    if (proxy_list.contains(ip)) {
        return false;
    }

    if (bypass_rules.contains(ip)) {
        return true;
    }

    if (proxy_rules.contains(ip)) {
        return false;
    }

    if (!host.empty() && host != ip) {
        if (bypass_rules.contains(host)) {
            return true;
        }

        if (proxy_rules.contains(host)) {
            return false;
        }
    }

    return acl_mode == black_list;
}

bool access_control_list::is_block_outbound(std::string_view ip, std::string_view host) const {
    if (outbound_block_list.contains(ip) || outbound_block_rules.contains(ip)) {
        return true;
    }

    if (!host.empty() && host != ip) {
        if (outbound_block_rules.contains(host)) {
            return true;
        }
    }

    return acl_mode == black_list;
}
