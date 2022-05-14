#include "convert.h"

std::string method_to_string(crypto::aead::method method) {
    switch (method) {
        using enum crypto::aead::method;
    case chacha20_poly1305:
        return "chacha20-ietf-poly1305";
    case aes_128_gcm:
        return "aes-128-gcm";
    case aes_256_gcm:
        return "aes-256-gcm";
    }
}
