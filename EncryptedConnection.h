#ifndef ENCRYPTED_SESSION_H
#define ENCRYPTED_SESSION_H

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include <cryptopp/randpool.h>

#include "AEAD.h"
#include "Connection.h"
#include "io.h"

// EncryptedConnection decrypts the data after receiving it,
// and encrypts the data before sending it.
class EncryptedConnection {
public:
    EncryptedConnection(asio::ip::tcp::socket s, asio::const_buffer key);

    asio::awaitable<std::size_t> read(asio::mutable_buffer buffer);
    asio::awaitable<std::size_t> write(asio::const_buffer buffer);
    void close();

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

asio::awaitable<void> readSalt(Reader auto& r, const std::unique_ptr<AEAD>& deC) {
    if (deC->salt()) {
        co_return;
    }

    std::vector<std::uint8_t> salt(deC->saltSize());
    co_await readFull(r, asio::buffer(salt));
    deC->setSalt(asio::buffer(salt));
}

asio::awaitable<std::size_t> readEncryptedPayload(Reader auto& r, const std::unique_ptr<AEAD>& deC,
                                                  asio::mutable_buffer out) {
    std::size_t tagSize = deC->tagSize();
    std::vector<std::uint8_t> buf(AEAD::MaximumPayloadSize + tagSize);

    // read encrypted length
    std::size_t n = co_await readFull(r, asio::buffer(buf.data(), 2 + tagSize));

    std::uint16_t payloadLen = 0;
    deC->decrypt(asio::buffer(buf.data(), n), asio::buffer(&payloadLen, 2));
    payloadLen = ntohs(payloadLen);

    // read encrypted payload
    n = co_await readFull(r, asio::buffer(buf.data(), payloadLen + tagSize));
    deC->decrypt(asio::buffer(buf.data(), n), asio::buffer(out.data(), payloadLen));

    co_return payloadLen;
}

asio::awaitable<void> writeSalt(Writer auto& w, const std::unique_ptr<AEAD>& enC) {
    if (enC->salt()) {
        co_return;
    }

    static CryptoPP::RandomPool rand;
    std::size_t saltSize = enC->saltSize();
    std::vector<std::uint8_t> salt(saltSize);

    rand.GenerateBlock(salt.data(), saltSize);
    enC->setSalt(asio::buffer(salt));
    co_await w.write(asio::buffer(salt));
}

asio::awaitable<std::size_t> writeUnencryptedPayload(Writer auto& w, const std::unique_ptr<AEAD>& enC,
                                                     asio::const_buffer in) {
    std::size_t remaining = in.size();
    std::size_t nWrite = 0;
    std::size_t tagSize = enC->tagSize();
    std::vector<std::uint8_t> buf(AEAD::MaximumPayloadSize + tagSize);
    const std::uint8_t* data = static_cast<const std::uint8_t*>(in.data());
    constexpr std::size_t maximumPayloadSize = AEAD::MaximumPayloadSize;

    while (remaining > 0) {
        std::uint16_t payloadLen = static_cast<std::uint16_t>(remaining);
        if (remaining > maximumPayloadSize) {
            payloadLen = static_cast<std::uint16_t>(maximumPayloadSize);
        }

        std::uint16_t len = htons(payloadLen);

        // write encrypted length of payload
        enC->encrypt(asio::buffer(&len, 2), asio::buffer(buf.data(), 2 + tagSize));
        co_await w.write(asio::buffer(buf.data(), 2 + tagSize));

        // write encrypted payload
        enC->encrypt(asio::buffer(data + nWrite, payloadLen),
                     asio::buffer(buf.data(), payloadLen + tagSize));
        co_await w.write(asio::buffer(buf.data(), payloadLen + tagSize));

        nWrite += payloadLen;
        remaining -= payloadLen;
    }

    co_return nWrite;
}

#endif
