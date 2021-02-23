#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <asio/ts/buffer.hpp>
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

    static void HKDFSHA1(asio::const_buffer key, asio::const_buffer salt,
                         asio::mutable_buffer subkey) {
        if (key.size() != KeySize) {
            throw AEAD::LengthError{"The length of key is wrong", KeySize, key.size()};
        }

        if (subkey.size() != KeySize) {
            throw AEAD::LengthError{"The length of subkey is wrong", KeySize, subkey.size()};
        }

        if (salt.size() != SaltSize) {
            throw AEAD::LengthError{"The length of salt is wrong", SaltSize, salt.size()};
        }

        constexpr auto InfoLen = 9;
        constexpr std::uint8_t Info[InfoLen] = {'s', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'};

        const std::uint8_t* secret = static_cast<const std::uint8_t*>(key.data());
        const std::uint8_t* pSalt = static_cast<const std::uint8_t*>(salt.data());
        std::uint8_t* derived = static_cast<std::uint8_t*>(subkey.data());
        CryptoPP::HKDF<CryptoPP::SHA1> hkdf;

        hkdf.DeriveKey(derived, KeySize, secret, KeySize, pSalt, SaltSize, Info, InfoLen);
    }

    ChaCha20Poly1305(asio::const_buffer key) {
        if (key.size() != KeySize) {
            throw AEAD::LengthError{"The length of key is wrong", KeySize, key.size()};
        }

        std::memcpy(this->key, key.data(), KeySize);
    }

    void encrypt(asio::const_buffer plaintext, asio::mutable_buffer ciphertext) override {
        checkParameters(plaintext, ciphertext);

        cipher.SetKeyWithIV(this->key, KeySize, nonce, NonceSize);

        std::uint8_t* pCiphertext = static_cast<std::uint8_t*>(ciphertext.data());
        const std::uint8_t* message = static_cast<const std::uint8_t*>(plaintext.data());
        cipher.EncryptAndAuthenticate(pCiphertext, pCiphertext + plaintext.size(), TagSize, nonce,
                                      NonceSize, nullptr, 0, message, plaintext.size());

        increment(asio::buffer(nonce));
    }

    void decrypt(asio::const_buffer ciphertext, asio::mutable_buffer plaintext) override {
        checkParameters(plaintext, ciphertext);

        cipher.SetKeyWithIV(key, KeySize, nonce, NonceSize);

        const std::uint8_t* pCiphertext = static_cast<const std::uint8_t*>(ciphertext.data());
        std::uint8_t* message = static_cast<std::uint8_t*>(plaintext.data());
        if (cipher.DecryptAndVerify(message, pCiphertext + plaintext.size(), TagSize, nonce,
                                    NonceSize, nullptr, 0, pCiphertext,
                                    plaintext.size()) == false) {
            throw AEAD::DecryptionError{"Decryption error"};
        }

        increment(asio::buffer(nonce));
    }

    bool salt() override { return havaSalt; }

    void setSalt(asio::const_buffer salt) override {
        std::array<std::uint8_t, KeySize> subkey;
        ChaCha20Poly1305::HKDFSHA1(asio::buffer(key), salt, asio::buffer(subkey));
        std::memcpy(key, subkey.data(), KeySize);

        havaSalt = true;
    }

    std::size_t keySize() override { return KeySize; }
    std::size_t saltSize() override { return SaltSize; }
    std::size_t nonceSize() override { return NonceSize; }
    std::size_t tagSize() override { return TagSize; }

private:
    void checkParameters(asio::const_buffer plaintext, asio::const_buffer ciphertext) {
        if (ciphertext.size() != plaintext.size() + TagSize) {
            throw AEAD::LengthError{"The length of plaintext is wrong", plaintext.size() + TagSize,
                                    plaintext.size()};
        }

        if (plaintext.size() > MaximumPayloadSize) {
            throw AEAD::LengthError{"The length of plaintext is too long", MaximumPayloadSize,
                                    plaintext.size()};
        }
    }

    CryptoPP::ChaCha20Poly1305_Final<T_IsEncryption> cipher;
    std::uint8_t key[KeySize];
    std::uint8_t nonce[NonceSize]{};
    bool havaSalt = false;
};

#endif
