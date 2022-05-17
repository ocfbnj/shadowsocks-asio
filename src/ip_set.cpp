#include <cassert>
#include <functional>
#include <optional>
#include <vector>

#include <asio/ts/internet.hpp>

#include "ip_set.h"

namespace {
constexpr std::size_t ipv4_bits = 32;
constexpr std::size_t ipv6_bits = 128;

// Returns ip address, network byte order.
std::optional<std::vector<std::uint8_t>> parse_ip_address(std::string_view ip) {
    std::error_code err;
    const asio::ip::address addr = asio::ip::make_address(ip, err);

    if (err) {
        return std::nullopt;
    }

    if (addr.is_v4()) {
        const auto bytes = addr.to_v4().to_bytes();
        return std::vector<std::uint8_t>{bytes.begin(), bytes.end()};
    } else if (addr.is_v6()) {
        const auto bytes = addr.to_v6().to_bytes();
        return std::vector<std::uint8_t>{bytes.begin(), bytes.end()};
    }

    return std::nullopt;
}

// Returns bit i in bits, network byte order.
bool get_bit(std::span<const std::uint8_t> bits, std::size_t i) {
    assert(i < bits.size() * 8);

    const auto bank = i / 8;
    const auto offset = i % 8;

    return (bits[bank] >> (7 - offset)) & 1;
}
} // namespace

bool ip_set::insert(std::string_view cidr) {
    const auto pos = cidr.find('/');
    if (pos == std::string::npos) {
        return false;
    }

    const auto ip = parse_ip_address(cidr.substr(0, pos));
    if (!ip) {
        return false;
    }

    try {
        std::uint8_t bits = stoul(std::string{cidr.substr(pos + 1)});
        return insert(*ip, bits);
    } catch (const std::exception& e) {
        return false;
    }
}

bool ip_set::insert(std::span<const std::uint8_t> ip, std::uint8_t bits) {
    const auto ipbits = ip.size() * 8;

    if (ipbits != ipv4_bits && ipbits != ipv6_bits) {
        return false;
    }

    if (ipbits == ipv4_bits && bits > ipv4_bits) {
        return false;
    }

    if (ipbits == ipv6_bits && bits > ipv6_bits) {
        return false;
    }

    if (ipbits == ipv4_bits) {
        return ipv4.insert(ip, bits);
    }

    return ipv6.insert(ip, bits);
}

bool ip_set::contains(std::string_view ip_str) const {
    const auto ip = parse_ip_address(ip_str);
    if (!ip) {
        return false;
    }

    return contains(*ip);
}

bool ip_set::contains(std::span<const std::uint8_t> ip) const {
    const auto ipbits = ip.size() * 8;

    if (ipbits != ipv4_bits && ipbits != ipv6_bits) {
        return false;
    }

    if (ipbits == ipv4_bits) {
        return ipv4.contains(ip);
    }

    return ipv6.contains(ip);
}

void ip_set::clear() {
    ipv4.clear();
    ipv6.clear();
}

ip_set::trie::trie(trie&& other) noexcept : root(other.root) {
    other.root.left = nullptr;
    other.root.right = nullptr;
}

ip_set::trie& ip_set::trie::operator=(trie&& other) noexcept {
    if (&other == this) {
        return *this;
    }

    root = other.root;
    other.root.left = nullptr;
    other.root.right = nullptr;

    return *this;
}

ip_set::trie::~trie() {
    clear();
}

bool ip_set::trie::insert(std::span<const std::uint8_t> ip, std::uint8_t bits) {
    trie_node* node = &root;

    if (bits == 0) {
        return false;
    }

    for (std::uint8_t i = 0; i != bits; i++) {
        if (get_bit(ip, i)) {
            if (!node->right) {
                node->right = new trie_node{};
            }
            node = node->right;
        } else {
            if (!node->left) {
                node->left = new trie_node{};
            }
            node = node->left;
        }

        if (i == bits - 1) {
            node->is_complete = true;
        }
    }

    return true;
}

bool ip_set::trie::contains(std::span<const std::uint8_t> ip) const {
    const auto ipbits = ip.size() * 8;
    const trie_node* node = &root;

    for (std::uint8_t i = 0; i != ipbits; i++) {
        if (get_bit(ip, i)) {
            node = node->right;
        } else {
            node = node->left;
        }

        if (!node) {
            return false;
        }

        if (node->is_complete) {
            return true;
        }
    }

    return false;
}

void ip_set::trie::clear() {
    std::function<void(trie_node*)> free = [&](trie_node* node) {
        if (node) {
            free(node->left);
            free(node->right);
            delete node;
        }
    };

    free(root.left);
    free(root.right);

    root.left = nullptr;
    root.right = nullptr;
}
