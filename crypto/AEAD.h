#ifndef AEAD_H
#define AEAD_H

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "type.h"

template <bool IsEncryption>
class ChaCha20Poly1305Base;

template <bool IsEncryption>
class AES256GCMBase;

template <bool IsEncryption>
class AES128GCMBase;

class AEAD;

using AEADPtr = std::unique_ptr<AEAD>;

void increment(BytesView num);
void deriveKey(ConstBytesView password, BytesView key);
void hkdfSha1(BytesView key, BytesView salt, BytesView subkey);

// AEAD class is the interface for AEAD Cipher.
class AEAD {
public:
    using Ciphers = std::pair<AEADPtr, AEADPtr>;

    static constexpr auto MaximumPayloadSize = 0x3FFF;

    static constexpr auto MaximumKeySize = 32;
    static constexpr auto MaximumSaltSize = 32;
    static constexpr auto MaximumNonceSize = 12;
    static constexpr auto MaximumTagSize = 16;

    static constexpr std::string_view Info = "ss-subkey";

    enum Cipher {
        ChaCha20Poly1305,
        AES256GCM,
        AES128GCM,
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

    template <bool IsEncryption>
    static std::unique_ptr<AEAD> create(Cipher type, BytesView key) {
        switch (type) {
        case AEAD::ChaCha20Poly1305:
            return std::make_unique<ChaCha20Poly1305Base<IsEncryption>>(key);
        case AEAD::AES256GCM:
            return std::make_unique<AES256GCMBase<IsEncryption>>(key);
        case AEAD::AES128GCM:
            return std::make_unique<AES128GCMBase<IsEncryption>>(key);
        default:
            break;
        }

        return {};
    }

    static Ciphers makeCiphers(Cipher type, ConstBytesView password);
    static Ciphers makeCiphers(Cipher type, std::string_view password);

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

// AEADBase implements the AEAD interface.
template <typename CipherType, Size KeySize, Size SaltSize, Size NonceSize, Size TagSize>
class AEADBase : public AEAD {
public:
    AEADBase(BytesView key) {
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
    std::array<Byte, NonceSize> nonce{};
    bool havaSalt = false;
};

#endif
