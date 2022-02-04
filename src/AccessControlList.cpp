#include <cctype>
#include <fstream>
#include <stdexcept>

#include <fmt/format.h>

#include "AccessControlList.h"

namespace {
void trim(std::string& str) {
    str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](char c) { return !std::isspace(c); }));
    str.erase(std::find_if(str.rbegin(), str.rend(), [](char c) { return !std::isspace(c); }).base(), str.end());
}
} // namespace

AccessControlList AccessControlList::fromFile(const std::string& path) {
    AccessControlList acl;

    std::ifstream ifs{path.data(), std::ifstream::in | std::ifstream::binary};
    if (!ifs) {
        throw std::runtime_error{fmt::format("Cannot open acl file: {}", path)};
    }

    IPSet* cur_list = &acl.bypass_list;

    std::string line;
    while (ifs >> line) {
        line.erase(std::find(line.begin(), line.end(), '#'), line.end());
        trim(line);

        if (line.empty()) {
            continue;
        }

        if (line == "[proxy_all]") {
            acl.mode = WhiteList;
        } else if (line == "[bypass_all]") {
            acl.mode = BlackList;
        } else if (line == "[bypass_list]") {
            cur_list = &acl.bypass_list;
        } else if (line == "[proxy_list]") {
            cur_list = &acl.proxy_list;
        } else {
            cur_list->insert(line);
        }
    }

    return acl;
}

bool AccessControlList::is_bypass(const std::string& ip) const {
    if (bypass_list.contains(ip)) {
        return true;
    }

    if (proxy_list.contains(ip)) {
        return false;
    }

    return mode == BlackList;
}
