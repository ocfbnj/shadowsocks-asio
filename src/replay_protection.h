#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include <array>
#include <cstdint>
#include <mutex>
#include <span>

#include <bloom_filter.hpp>

// See https://github.com/shadowsocks/shadowsocks-org/issues/44
class replay_protection {
public:
    static replay_protection& get();

    void insert(std::span<const std::uint8_t> element);
    bool contains(std::span<const std::uint8_t> element);

private:
    replay_protection();

    std::array<bloom_filter, 2> filters;
    int current = 0;
    int count = 1'000'000; // one million

    std::mutex mtx;
};

#endif
