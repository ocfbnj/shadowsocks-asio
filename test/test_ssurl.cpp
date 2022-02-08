#include <string>

#include <gtest/gtest.h>

#include "../src/SSURL.h"

struct TestCase {
    std::string url;
    SSURL ssurl;
};

const TestCase testCases[]{
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

TEST(SSURL, parse) {
    for (const TestCase& testCase : testCases) {
        SSURL ssurl = SSURL::parse(testCase.url);
        ASSERT_EQ(ssurl, testCase.ssurl);
    }
}

TEST(SSURL, encode) {
    for (const TestCase& testCase : testCases) {
        std::string url = testCase.ssurl.encode();
        ASSERT_EQ(url, testCase.url);
    }
}
