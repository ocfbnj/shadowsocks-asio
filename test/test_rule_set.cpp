#include <string_view>

#include <gtest/gtest.h>

#include "../src/rule_set.h"

TEST(insert, valid) {
    rule_set set;

    std::string_view rules[] = {
        R"((^|\.)030buy\.com$)",
        R"((^|\.)0rz\.tw$)",
        R"((^|\.)1000giri\.net$)",
        R"((^|\.)100ke\.org$)",
        R"((^|\.)10conditionsoflove\.com$)",
        R"((^|\.)10musume\.com$)",
        R"((^|\.)10\.tt$)",
        R"((^|\.)123rf\.com$)",
        R"((^|\.)12bet\.com$)",
        R"((^|\.)12vpn\.com$)",
        R"((^|\.)12vpn\.net$)",
    };

    for (auto rule : rules) {
        ASSERT_EQ(set.insert(rule), true);
    }

    ASSERT_EQ(set.contains("030buy.com"), true);
    ASSERT_EQ(set.contains("12vpn.com"), true);
    ASSERT_EQ(set.contains(".12vpn.com"), true);
    ASSERT_EQ(set.contains("34.12vpn.com"), true);

    ASSERT_EQ(set.contains("1112vpn.com"), false);
    ASSERT_EQ(set.contains("12vpn.com "), false);
    ASSERT_EQ(set.contains("12vpn.comm"), false);
    ASSERT_EQ(set.contains("2vpn.net.com"), false);
    ASSERT_EQ(set.contains("2vpn.netccom"), false);
}

TEST(insert, invalid) {
    rule_set set;

    std::string_view rules[] = {
        R"())",
        R"(\d099()",
    };

    for (auto rule : rules) {
        ASSERT_EQ(set.insert(rule), false);
    }
}
