#ifndef OCFBNJ_CRYPTO_AEAD_H
#define OCFBNJ_CRYPTO_AEAD_H

#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <crypto/crypto.h>

#include "type.h"

class AEAD;

using AEADPtr = std::unique_ptr<AEAD>;

// AEAD class is the interface for AEAD Cipher.
// See https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
class AEAD {
public:
    // Encryption and decryption ciphers.
    using Ciphers = std::pair<AEADPtr, AEADPtr>;

    static constexpr auto MaximumPayloadSize = 0x3FFF;
    static constexpr auto MaximumKeySize = 32;
    static constexpr auto MaximumSaltSize = 32;
    static constexpr auto MaximumNonceSize = 12;
    static constexpr auto MaximumTagSize = 16;
    static constexpr std::string_view Info = "ss-subkey";

    // Compliant Shadowsocks implementations must support AEAD_CHACHA20_POLY1305.
    // Implementations for devices with hardware AES acceleration should also implement AEAD_AES_128_GCM and AEAD_AES_256_GCM.
    // See https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
    enum Method {
        ChaCha20Poly1305,
        AES128GCM,
        AES256GCM,
        Invalid
    };

    class DecryptionError : public std::exception {
    public:
        DecryptionError(std::string_view msg) noexcept : msg(msg) {}
        ~DecryptionError() noexcept = default;

        const char* what() const noexcept override {
            return msg.data();
        }

    private:
        std::string msg;
    };

    // getKeySize returns the key size of the encryption method.
    static Size getKeySize(Method method);

    // makeCiphers returns the encryption and decryption ciphers.
    static Ciphers makeCiphers(Method method, ConstBytesView key);

    virtual ~AEAD() = default;

    virtual void encrypt(BytesView plaintext, BytesView ciphertext) = 0;
    virtual void decrypt(BytesView ciphertext, BytesView plaintext) = 0;

    virtual bool salt() const = 0;
    virtual void setSalt(BytesView salt) = 0;

    virtual Size keySize() const = 0;
    virtual Size saltSize() const = 0;
    virtual Size nonceSize() const = 0;
    virtual Size tagSize() const = 0;
};

// AEADImpl implements the AEAD interface.
// See https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
template <typename CipherType,
          Size KeySize,
          Size SaltSize,
          Size NonceSize,
          Size TagSize>
class AEADImpl : public AEAD {
public:
    AEADImpl(ConstBytesView key) : nonce(), havaSalt(false) {
        std::copy(key.begin(), key.end(), this->key.begin());
    }

    void encrypt(BytesView plaintext, BytesView ciphertext) override {
        cipher.SetKeyWithIV(key.data(), KeySize, nonce.data(), NonceSize);
        cipher.EncryptAndAuthenticate(ciphertext.data(),
                                      ciphertext.data() + plaintext.size(), TagSize,
                                      nonce.data(), NonceSize,
                                      nullptr, 0,
                                      plaintext.data(), plaintext.size());

        increment(nonce);
    }

    void decrypt(BytesView ciphertext, BytesView plaintext) override {
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

    bool salt() const override { return havaSalt; }

    void setSalt(BytesView salt) override {
        std::array<Byte, KeySize> subkey;
        hkdfSha1(key, salt, subkey);
        std::copy(subkey.begin(), subkey.end(), key.begin());

        havaSalt = true;
    }

    Size keySize() const override { return KeySize; }
    Size saltSize() const override { return SaltSize; }
    Size nonceSize() const override { return NonceSize; }
    Size tagSize() const override { return TagSize; }

private:
    CipherType cipher;
    std::array<Byte, KeySize> key;
    std::array<Byte, NonceSize> nonce;

    bool havaSalt;
};

#endif
