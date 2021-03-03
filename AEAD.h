#ifndef AEAD_H
#define AEAD_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

void increment(std::span<std::uint8_t> num);
void deriveKey(std::span<std::uint8_t> password, std::size_t keySize, std::span<std::uint8_t> key);

class AEAD {
public:
    static constexpr auto MaximumPayloadSize = 0x3FFF;

    static constexpr auto MaximumKeySize = 32;
    static constexpr auto MaximumSaltSize = 32;
    static constexpr auto MaximumNonceSize = 12;
    static constexpr auto MaximumTagSize = 16;

    static constexpr std::string_view Info = "ss-subkey";

    class LengthError : public std::exception {
    public:
        LengthError(std::string_view msg, std::size_t expect, std::size_t actual) noexcept
            : msg(msg), expect(expect), actual(actual) {}
        ~LengthError() noexcept = default;

        const char* what() const noexcept override {
            std::string w = msg + ": " +
                            "expecting " + std::to_string(expect) +
                            ", but " + std::to_string(actual);
            return std::data(w);
        }

    private:
        std::size_t expect;
        std::size_t actual;
        std::string msg;
    };

    class DecryptionError : public std::exception {
    public:
        DecryptionError(std::string_view msg) noexcept : msg(msg) {}
        ~DecryptionError() noexcept = default;

        const char* what() const noexcept override {
            return std::data(msg);
        }

    private:
        std::string msg;
    };

    virtual ~AEAD() = default;

    virtual void encrypt(std::span<std::uint8_t> plaintext, std::span<std::uint8_t> ciphertext) = 0;
    virtual void decrypt(std::span<std::uint8_t> ciphertext, std::span<std::uint8_t> plaintext) = 0;

    virtual bool salt() = 0;
    virtual void setSalt(std::span<std::uint8_t> salt) = 0;

    virtual std::size_t keySize() = 0;
    virtual std::size_t saltSize() = 0;
    virtual std::size_t nonceSize() = 0;
    virtual std::size_t tagSize() = 0;
};

#endif
