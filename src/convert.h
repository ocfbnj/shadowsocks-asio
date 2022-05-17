#ifndef CONVERT_H
#define CONVERT_H

#include <optional>
#include <string>
#include <string_view>

#include <crypto/aead.h>

constexpr std::optional<crypto::aead::method> method_from_string(std::string_view str) {
    if (str == "chacha20-ietf-poly1305") {
        return crypto::aead::chacha20_poly1305;
    }

    if (str == "aes-128-gcm") {
        return crypto::aead::aes_128_gcm;
    }

    if (str == "aes-256-gcm") {
        return crypto::aead::aes_256_gcm;
    }

    return std::nullopt;
}

std::string method_to_string(crypto::aead::method method);

#endif
