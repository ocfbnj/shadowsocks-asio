#include <algorithm>

#include "rule_set.h"

bool rule_set::insert(std::string_view rule) {
    try {
        std::regex re{rule.data()};
        rules.emplace_back(std::move(re));
    } catch (const std::exception& e) {
        return false;
    }

    return true;
}

bool rule_set::contains(std::string_view host) const {
    return std::any_of(rules.begin(), rules.end(), [host](const std::regex& re) {
        return std::regex_search(host.data(), re);
    });
}
