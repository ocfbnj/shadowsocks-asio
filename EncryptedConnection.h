#ifndef ENCRYPTED_SESSION_H
#define ENCRYPTED_SESSION_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <cryptopp/randpool.h>

#include "AEAD.h"
#include "Connection.h"
#include "io.h"

// EncryptedConnection decrypts the data after receiving it,
// and encrypts the data before sending it.
class EncryptedConnection {
public:
    EncryptedConnection(asio::ip::tcp::socket s, std::span<std::uint8_t> key);

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<std::uint8_t> buffer);
    void close();

private:
    static constexpr auto MaximumMessageSize = 2 + AEAD::MaximumPayloadSize + 2 * AEAD::MaximumTagSize;

    // Connection is not inherited because we want to use its methods directly.
    Connection conn;

    std::unique_ptr<AEAD> enC;
    std::unique_ptr<AEAD> deC;

    // When the buffer for calling the read function is too small, temporarily put it in buf.
    std::array<std::uint8_t, MaximumMessageSize> buf;
    std::size_t index = 0;
    std::size_t remaining = 0;
};

asio::awaitable<void> readSalt(Reader auto& r, const std::unique_ptr<AEAD>& deC) {
    if (deC->salt()) {
        co_return;
    }

    std::vector<std::uint8_t> salt(deC->saltSize());
    co_await readFull(r, salt);
    deC->setSalt(salt);
}

asio::awaitable<std::size_t> readEncryptedPayload(Reader auto& r, const std::unique_ptr<AEAD>& deC,
                                                  std::span<std::uint8_t> out) {
    std::size_t tagSize = deC->tagSize();
    std::vector<std::uint8_t> buf(AEAD::MaximumPayloadSize + tagSize);

    // read encrypted length
    std::size_t n = co_await readFull(r, std::span{std::data(buf), 2 + tagSize});

    std::uint16_t payloadLen = 0;
    deC->decrypt(std::span{std::data(buf), n}, std::span{reinterpret_cast<std::uint8_t*>(&payloadLen), 2});
    payloadLen = ntohs(payloadLen);

    // read encrypted payload
    n = co_await readFull(r, std::span{std::data(buf), payloadLen + tagSize});
    deC->decrypt(std::span{std::data(buf), n}, std::span{std::data(out), payloadLen});

    co_return payloadLen;
}

asio::awaitable<void> writeSalt(Writer auto& w, const std::unique_ptr<AEAD>& enC) {
    if (enC->salt()) {
        co_return;
    }

    static CryptoPP::RandomPool rand;
    std::size_t saltSize = enC->saltSize();
    std::vector<std::uint8_t> salt(saltSize);

    rand.GenerateBlock(std::data(salt), saltSize);
    enC->setSalt(salt);
    co_await w.write(salt);
}

asio::awaitable<std::size_t> writeUnencryptedPayload(Writer auto& w, const std::unique_ptr<AEAD>& enC,
                                                     std::span<std::uint8_t> in) {
    std::size_t remaining = std::size(in);
    std::size_t nWrite = 0;
    std::size_t tagSize = enC->tagSize();
    std::vector<std::uint8_t> buf(AEAD::MaximumPayloadSize + tagSize);

    while (remaining > 0) {
        std::uint16_t payloadLen = static_cast<std::uint16_t>(remaining);
        if (remaining > AEAD::MaximumPayloadSize) {
            payloadLen = static_cast<std::uint16_t>(AEAD::MaximumPayloadSize);
        }

        std::uint16_t len = htons(payloadLen);

        // write encrypted length of payload
        enC->encrypt(std::span{reinterpret_cast<std::uint8_t*>(&len), 2},
                     std::span{std::data(buf), 2 + tagSize});
        co_await w.write(std::span<std::uint8_t>{std::data(buf), 2 + tagSize});

        // write encrypted payload
        enC->encrypt(std::span{std::data(in) + nWrite, payloadLen},
                     std::span{std::data(buf), payloadLen + tagSize});
        co_await w.write(std::span<std::uint8_t>{std::data(buf), payloadLen + tagSize});

        nWrite += payloadLen;
        remaining -= payloadLen;
    }

    co_return nWrite;
}

#endif
