#include <cctype>
#include <fstream>
#include <stdexcept>

#include <fmt/format.h>

#include "AccessControlList.h"

namespace {
void trimComment(std::string& str) {
    str.erase(std::find(str.begin(), str.end(), '#'), str.end());
}

void trimSpace(std::string& str) {
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

    IpSet* curList = &acl.bypassList;

    std::string line;
    while (std::getline(ifs, line)) {
        trimComment(line);
        trimSpace(line);

        if (line.empty()) {
            continue;
        }

        if (line == "[proxy_all]") {
            acl.mode = WhiteList;
        } else if (line == "[bypass_all]") {
            acl.mode = BlackList;
        } else if (line == "[bypass_list]") {
            curList = &acl.bypassList;
        } else if (line == "[proxy_list]") {
            curList = &acl.proxyList;
        } else {
            curList->insert(line);
        }
    }

    return acl;
}

bool AccessControlList::isBypass(const std::string& ip) const {
    if (bypassList.contains(ip)) {
        return true;
    }

    if (proxyList.contains(ip)) {
        return false;
    }

    return mode == BlackList;
}
