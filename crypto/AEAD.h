#ifndef AEAD_H
#define AEAD_H

#include <string>
#include <string_view>

#include "type.h"

void increment(BytesView num);
void deriveKey(ConstBytesView password, BytesView key);

class AEAD {
public:
    static constexpr auto MaximumPayloadSize = 0x3FFF;

    static constexpr auto MaximumKeySize = 32;
    static constexpr auto MaximumSaltSize = 32;
    static constexpr auto MaximumNonceSize = 12;
    static constexpr auto MaximumTagSize = 16;

    static constexpr std::string_view Info = "ss-subkey";

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

    virtual ~AEAD() = default;

    virtual void encrypt(BytesView plaintext, BytesView ciphertext) = 0;
    virtual void decrypt(BytesView ciphertext, BytesView plaintext) = 0;

    virtual bool salt() = 0;
    virtual void setSalt(BytesView salt) = 0;

    virtual Size keySize() = 0;
    virtual Size saltSize() = 0;
    virtual Size nonceSize() = 0;
    virtual Size tagSize() = 0;
};

#endif
