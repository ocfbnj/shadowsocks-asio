#ifndef ENCRYPTED_CONNECTION_H
#define ENCRYPTED_CONNECTION_H

#include <array>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

#include <crypto/aead/AEAD.h>

#include "Connection.h"

// EncryptedConnection decrypts the data after receiving it,
// and encrypts the data before sending it.
class EncryptedConnection {
public:
    class DuplicateSalt : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    EncryptedConnection(TCPSocket s, crypto::AEAD::Method method, std::span<const std::uint8_t> key);

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<const std::uint8_t> buffer);

    void close();

    void setReadTimeout(int val);

private:
    static constexpr std::size_t MaximumPayloadSize = 0x3FFF;
    static constexpr std::size_t MaximumTagSize = 16;
    static constexpr std::size_t MaximumMessageSize = 2 + MaximumPayloadSize + 2 * MaximumTagSize;
    static constexpr std::size_t NonceSize = 12;

    std::size_t saltSize() const;

    void encrypt(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> ciphertext);
    void decrypt(std::span<const std::uint8_t> ciphertext, std::span<std::uint8_t> plaintext);

    asio::awaitable<std::size_t> readEncryptedPayload(std::span<std::uint8_t> out);
    asio::awaitable<std::size_t> writeUnencryptedPayload(std::span<const std::uint8_t> in);

    // Connection is not inherited because we want to use its methods directly.
    Connection conn;

    crypto::AEAD cipher;
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> encNonce;
    std::vector<std::uint8_t> decNonce;
    std::vector<std::uint8_t> inSalt;
    std::vector<std::uint8_t> outSalt;

    // When the buffer for calling the read function is too small, temporarily put it in buf.
    std::array<std::uint8_t, MaximumMessageSize> buf;
    std::size_t index = 0;
    std::size_t remaining = 0;
};

#endif
