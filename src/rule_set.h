#ifndef RULE_SET_H
#define RULE_SET_H

#include <regex>
#include <string_view>
#include <vector>

class rule_set {
public:
    bool insert(std::string_view rule);
    bool contains(std::string_view host) const;

private:
    std::vector<std::regex> rules;
};

#endif
