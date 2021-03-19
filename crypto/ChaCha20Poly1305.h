#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <algorithm>
#include <array>
#include <cassert>

#include <cryptopp/chachapoly.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>

#include "AEAD.h"
#include "type.h"

template <bool T_IsEncryption = true>
class ChaCha20Poly1305 : public AEAD {
public:
    static constexpr auto KeySize = 32;
    static constexpr auto SaltSize = 32;
    static constexpr auto NonceSize = 12;
    static constexpr auto TagSize = 16;

    static void HKDFSHA1(BytesView key, BytesView salt,
                         BytesView subkey) {
        assert(key.size() == KeySize);
        assert(subkey.size() == KeySize);
        assert(salt.size() == SaltSize);

        CryptoPP::HKDF<CryptoPP::SHA1> hkdf;
        hkdf.DeriveKey(subkey.data(), KeySize,
                       key.data(), KeySize,
                       salt.data(), SaltSize,
                       reinterpret_cast<const u8*>(AEAD::Info.data()), AEAD::Info.size());
    }

    ChaCha20Poly1305(BytesView key) {
        assert(key.size() == KeySize);

        std::copy(key.begin(), key.end(), this->key.begin());
    }

    void encrypt(BytesView plaintext, BytesView ciphertext) override {
        assertParameters(plaintext, ciphertext);

        cipher.SetKeyWithIV(key.data(), KeySize, nonce.data(), NonceSize);
        cipher.EncryptAndAuthenticate(ciphertext.data(),
                                      ciphertext.data() + plaintext.size(), TagSize,
                                      nonce.data(), NonceSize,
                                      nullptr, 0,
                                      plaintext.data(), plaintext.size());

        increment(nonce);
    }

    void decrypt(BytesView ciphertext, BytesView plaintext) override {
        assertParameters(plaintext, ciphertext);

        cipher.SetKeyWithIV(key.data(), KeySize, nonce.data(), NonceSize);

        if (cipher.DecryptAndVerify(plaintext.data(),
                                    ciphertext.data() + plaintext.size(), TagSize,
                                    nonce.data(), NonceSize,
                                    nullptr, 0,
                                    ciphertext.data(), plaintext.size()) == false) {
            throw AEAD::DecryptionError{"Decryption error"};
        }

        increment(nonce);
    }

    bool salt() override { return havaSalt; }

    void setSalt(BytesView salt) override {
        std::array<u8, KeySize> subkey;
        HKDFSHA1(key, salt, subkey);
        std::copy(subkey.begin(), subkey.end(), key.begin());

        havaSalt = true;
    }

    Size keySize() override { return KeySize; }
    Size saltSize() override { return SaltSize; }
    Size nonceSize() override { return NonceSize; }
    Size tagSize() override { return TagSize; }

private:
    void assertParameters(BytesView plaintext, BytesView ciphertext) {
        assert(ciphertext.size() == plaintext.size() + TagSize);
        assert(plaintext.size() <= MaximumPayloadSize);
    }

    CryptoPP::ChaCha20Poly1305_Final<T_IsEncryption> cipher;
    std::array<u8, KeySize> key;
    std::array<u8, NonceSize> nonce{};
    bool havaSalt = false;
};

#endif
