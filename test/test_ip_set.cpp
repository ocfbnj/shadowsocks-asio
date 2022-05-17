#include <string_view>

#include <gtest/gtest.h>

#include "../src/ip_set.h"

TEST(insert, valid) {
    ip_set set;

    std::string_view iplist[] = {
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "220.160.0.0/11",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::1/128",
        "::ffff:127.0.0.1/104",
        "fc00::/7",
        "fe80::/10",
        "2001:b28:f23d:f001::e/128",
    };

    for (auto ip : iplist) {
        ASSERT_EQ(set.insert(ip), true);
    }

    ASSERT_EQ(set.contains("0.0.0.1"), true);
    ASSERT_EQ(set.contains("127.0.0.1"), true);
    ASSERT_EQ(set.contains("192.168.0.1"), true);
    ASSERT_EQ(set.contains("255.255.255.255"), true);
    ASSERT_EQ(set.contains("220.181.38.148"), true);

    ASSERT_EQ(set.contains("::1"), true);
    ASSERT_EQ(set.contains("fc00::ffff"), true);
    ASSERT_EQ(set.contains("fe80::1234"), true);
    ASSERT_EQ(set.contains("::ffff:127.0.0.1"), true);
    ASSERT_EQ(set.contains("2001:b28:f23d:f001::e"), true);

    ASSERT_EQ(set.contains("::"), false);
}

TEST(insert, invalid) {
    ip_set set;

    std::string_view iplist[] = {
        "::1/129",
        "127.0.0.1",
        "127.0.0.1/ocfbnj",
        "127.0.0.1/128",
        "1.2.3",
    };

    for (auto ip : iplist) {
        ASSERT_EQ(set.insert(ip), false);
    }
}
