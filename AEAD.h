#ifndef AEAD_H
#define AEAD_H

#include <cstddef>
#include <string>

#include <asio/ts/buffer.hpp>

void increment(asio::mutable_buffer num);
void deriveKey(asio::const_buffer password, std::size_t keySize, asio::mutable_buffer key);

class AEAD {
public:
    static constexpr auto MaximumPayloadSize = 0x3FFF;

    static constexpr auto MaximumKeySize = 32;
    static constexpr auto MaximumSaltSize = 32;
    static constexpr auto MaximumNonceSize = 12;
    static constexpr auto MaximumTagSize = 16;

    class LengthError : public std::exception {
    public:
        LengthError(std::string msg, std::size_t expect, std::size_t actual) noexcept
            : msg(msg), expect(expect), actual(actual) {}
        ~LengthError() noexcept = default;

        const char* what() const noexcept override {
            std::string w = msg + ": " + "expecting " + std::to_string(expect) + ", but " +
                            std::to_string(actual);
            return w.c_str();
        }

    private:
        std::size_t expect;
        std::size_t actual;
        std::string msg;
    };

    class DecryptionError : public std::exception {
    public:
        DecryptionError(std::string msg) noexcept : msg(msg) {}
        ~DecryptionError() noexcept = default;

        const char* what() const noexcept override {
            return msg.c_str();
        }

    private:
        std::string msg;
    };

    virtual ~AEAD() = default;

    virtual void encrypt(asio::const_buffer plaintext, asio::mutable_buffer ciphertext) = 0;
    virtual void decrypt(asio::const_buffer ciphertext, asio::mutable_buffer plaintext) = 0;

    virtual bool salt() = 0;
    virtual void setSalt(asio::const_buffer salt) = 0;

    virtual std::size_t keySize() = 0;
    virtual std::size_t saltSize() = 0;
    virtual std::size_t nonceSize() = 0;
    virtual std::size_t tagSize() = 0;
};

#endif
