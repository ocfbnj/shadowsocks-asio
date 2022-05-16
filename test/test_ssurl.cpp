#include <string>

#include <gtest/gtest.h>

#include "../src/ss_url.h"

struct test_case {
    std::string url;
    ss_url ssurl;
};

const test_case test_cases[] = {
    {
        .url = "ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888",
        .ssurl = {
            .userinfo = {
                .method = "aes-128-gcm",
                .password = "test",
            },
            .hostname = "192.168.100.1",
            .port = "8888",
        },
    },
    {
        .url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpvY2Zibmo@ocfbnj.cn:8152",
        .ssurl = {
            .userinfo = {
                .method = "chacha20-ietf-poly1305",
                .password = "ocfbnj",
            },
            .hostname = "ocfbnj.cn",
            .port = "8152",
        },
    },
};

TEST(ss_url, parse) {
    for (const test_case& test_case : test_cases) {
        ss_url ssurl = ss_url::parse(test_case.url);
        ASSERT_EQ(ssurl, test_case.ssurl);
    }
}

TEST(ss_url, encode) {
    for (const test_case& test_case : test_cases) {
        std::string url = test_case.ssurl.encode();
        ASSERT_EQ(url, test_case.url);
    }
}
