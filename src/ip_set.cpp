#include <algorithm>
#include <cctype>
#include <functional>
#include <optional>

#include "ip_set.h"

namespace {
std::optional<std::uint32_t> parse_ip_address(const std::string& ip) {
    std::uint32_t res = 0;
    std::uint8_t num = 0;

    for (char c : ip) {
        if (!std::isdigit(c) && c != '.') {
            return {};
        }

        if (c == '.') {
            res = (res << 8) | (num & 0xFF);
            num = 0;
            continue;
        }

        num = num * 10 + (c - '0');
    }

    res = (res << 8) | (num & 0xFF);

    return res;
}
} // namespace

ip_set::ip_set(ip_set&& other) : root(other.root) {
    other.root.left = nullptr;
    other.root.right = nullptr;
}

ip_set& ip_set::operator=(ip_set&& other) {
    if (&other == this) {
        return *this;
    }

    root = other.root;
    other.root.left = nullptr;
    other.root.right = nullptr;

    return *this;
}

ip_set::~ip_set() {
    clear();
}

void ip_set::insert(const std::string& cidr) {
    auto pos = cidr.find('/');
    if (pos == std::string::npos) {
        return;
    }

    std::optional<std::uint32_t> ip = parse_ip_address(cidr.substr(0, pos));
    if (!ip.has_value()) {
        return;
    }

    std::uint8_t bits = stoul(cidr.substr(pos + 1));
    if (bits > 32) {
        return;
    }

    insert(ip.value(), bits);
}

void ip_set::insert(std::uint32_t ip, std::uint8_t bits) {
    TrieNode* node = &root;

    if (bits == 0) {
        return;
    }

    for (std::uint8_t i = 0; i != bits; i++) {
        std::uint8_t bit = (ip >> (31 - i)) & 1;
        if (bit) {
            if (!node->right) {
                node->right = new TrieNode{};
            }
            node = node->right;
        } else {
            if (!node->left) {
                node->left = new TrieNode{};
            }
            node = node->left;
        }

        if (i == bits - 1) {
            node->is_complete = true;
        }
    }
}

bool ip_set::contains(const std::string& ip) const {
    std::optional<std::uint32_t> addr = parse_ip_address(ip);
    if (!addr.has_value()) {
        return false;
    }

    std::uint32_t addr_value = addr.value();
    const TrieNode* node = &root;

    for (std::uint8_t i = 0; i != 32; i++) {
        std::uint8_t bit = (addr_value >> (31 - i)) & 1;
        if (bit) {
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

void ip_set::clear() {
    std::function<void(TrieNode*)> free = [&, this](TrieNode* node) {
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
