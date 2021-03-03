#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>

#include <cryptopp/chachapoly.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>

#include "AEAD.h"

template <bool T_IsEncryption = true>
class ChaCha20Poly1305 : public AEAD {
public:
    static constexpr auto KeySize = 32;
    static constexpr auto SaltSize = 32;
    static constexpr auto NonceSize = 12;
    static constexpr auto TagSize = 16;

    static void HKDFSHA1(std::span<std::uint8_t> key, std::span<std::uint8_t> salt,
                         std::span<std::uint8_t> subkey) {
        if (std::size(key) != KeySize) {
            throw AEAD::LengthError{"The length of key is wrong", KeySize, std::size(key)};
        }

        if (std::size(subkey) != KeySize) {
            throw AEAD::LengthError{"The length of subkey is wrong", KeySize, std::size(subkey)};
        }

        if (std::size(salt) != SaltSize) {
            throw AEAD::LengthError{"The length of salt is wrong", SaltSize, std::size(salt)};
        }

        std::uint8_t* secret = std::data(key);
        std::uint8_t* pSalt = std::data(salt);
        std::uint8_t* derived = std::data(subkey);
        CryptoPP::HKDF<CryptoPP::SHA1> hkdf;

        hkdf.DeriveKey(derived, KeySize,
                       secret, KeySize,
                       pSalt, SaltSize,
                       reinterpret_cast<const std::uint8_t*>(std::data(AEAD::Info)),
                       std::size(AEAD::Info));
    }

    ChaCha20Poly1305(std::span<std::uint8_t> key) {
        if (std::size(key) != KeySize) {
            throw AEAD::LengthError{"The length of key is wrong", KeySize, std::size(key)};
        }

        std::ranges::copy(key, std::ranges::begin(this->key));
    }

    void encrypt(std::span<std::uint8_t> plaintext, std::span<std::uint8_t> ciphertext) override {
        checkParameters(plaintext, ciphertext);

        cipher.SetKeyWithIV(std::data(key), KeySize, std::data(nonce), NonceSize);
        cipher.EncryptAndAuthenticate(std::data(ciphertext),
                                      std::data(ciphertext) + std::size(plaintext), TagSize,
                                      std::data(nonce), NonceSize,
                                      nullptr, 0,
                                      std::data(plaintext), std::size(plaintext));

        increment(nonce);
    }

    void decrypt(std::span<std::uint8_t> ciphertext, std::span<std::uint8_t> plaintext) override {
        checkParameters(plaintext, ciphertext);

        cipher.SetKeyWithIV(std::data(key), KeySize, std::data(nonce), NonceSize);

        if (cipher.DecryptAndVerify(std::data(plaintext),
                                    std::data(ciphertext) + std::size(plaintext), TagSize,
                                    std::data(nonce), NonceSize,
                                    nullptr, 0,
                                    std::data(ciphertext), std::size(plaintext)) == false) {
            throw AEAD::DecryptionError{"Decryption error"};
        }

        increment(nonce);
    }

    bool salt() override { return havaSalt; }

    void setSalt(std::span<std::uint8_t> salt) override {
        std::array<std::uint8_t, KeySize> subkey;
        ChaCha20Poly1305::HKDFSHA1(key, salt, subkey);
        std::ranges::copy(subkey, std::ranges::begin(key));

        havaSalt = true;
    }

    std::size_t keySize() override { return KeySize; }
    std::size_t saltSize() override { return SaltSize; }
    std::size_t nonceSize() override { return NonceSize; }
    std::size_t tagSize() override { return TagSize; }

private:
    void checkParameters(std::span<std::uint8_t> plaintext, std::span<std::uint8_t> ciphertext) {
        if (std::size(ciphertext) != std::size(plaintext) + TagSize) {
            throw AEAD::LengthError{"The length of plaintext is wrong", std::size(plaintext) + TagSize,
                                    std::size(plaintext)};
        }

        if (std::size(plaintext) > MaximumPayloadSize) {
            throw AEAD::LengthError{"The length of plaintext is too long", MaximumPayloadSize,
                                    std::size(plaintext)};
        }
    }

    CryptoPP::ChaCha20Poly1305_Final<T_IsEncryption> cipher;
    std::array<std::uint8_t, KeySize> key;
    std::array<std::uint8_t, NonceSize> nonce{};
    bool havaSalt = false;
};

#endif
