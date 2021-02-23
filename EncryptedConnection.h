#ifndef ENCRYPTED_SESSION_H
#define ENCRYPTED_SESSION_H

#include <array>
#include <cstdint>

#include "ChaCha20Poly1305.h"
#include "Connection.h"
#include "io.h"

// EncryptedConnection decrypts the data after receiving it,
// and encrypts the data before sending it.
class EncryptedConnection : public ReadWriteCloser {
public:
    EncryptedConnection(asio::ip::tcp::socket&& s, asio::const_buffer key);

    std::size_t read(asio::mutable_buffer buffer, asio::yield_context yield) override;
    std::size_t write(asio::const_buffer buffer, asio::yield_context yield) override;
    void close() override;

private:
    // Connection is not inherited because we want to use its methods directly.
    Connection conn;

    std::unique_ptr<AEAD> enC;
    std::unique_ptr<AEAD> deC;

    // When the buffer for calling the read function is too small, temporarily put it in buf.
    std::array<std::uint8_t, 2 + AEAD::MaximumPayloadSize + 2 * AEAD::MaximumTagSize> buf;
    std::size_t index = 0;
    std::size_t remaining = 0;
};

#endif
