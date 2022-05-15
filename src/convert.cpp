#include <cassert>

#include "convert.h"

std::string method_to_string(crypto::aead::method method) {
    switch (method) {
    case crypto::aead::chacha20_poly1305:
        return "chacha20-ietf-poly1305";
    case crypto::aead::aes_128_gcm:
        return "aes-128-gcm";
    case crypto::aead::aes_256_gcm:
        return "aes-256-gcm";
    default:
        assert(0);
        return "";
    }
}
