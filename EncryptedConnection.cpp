#include <array>
#include <memory>
#include <vector>

#include <cryptopp/randpool.h>

#include "EncryptedConnection.h"
#include "logger.h"

EncryptedConnection::EncryptedConnection(asio::ip::tcp::socket&& s, asio::const_buffer key)
    : conn(std::move(s)),
      enC(std::make_unique<ChaCha20Poly1305<true>>(key)),
      deC(std::make_unique<ChaCha20Poly1305<false>>(key)) {}

static void readSalt(Reader& r, const std::unique_ptr<AEAD>& deC, asio::yield_context yield) {
    if (deC->salt()) {
        return;
    }

    std::vector<std::uint8_t> salt(deC->saltSize());
    readFull(r, asio::buffer(salt), yield);
    deC->setSalt(asio::buffer(salt));
}

static std::size_t readEncryptedPayload(Reader& r, const std::unique_ptr<AEAD>& deC,
                                        asio::mutable_buffer out, asio::yield_context yield) {
    std::size_t tagSize = deC->tagSize();
    std::vector<std::uint8_t> buf(AEAD::MaximumPayloadSize + tagSize);

    // read encrypted length
    std::size_t n = readFull(r, asio::buffer(buf.data(), 2 + tagSize), yield);

    std::uint16_t payloadLen = 0;
    deC->decrypt(asio::buffer(buf.data(), n), asio::buffer(&payloadLen, 2));
    payloadLen = ntohs(payloadLen);

    // read encrypted payload
    n = readFull(r, asio::buffer(buf.data(), payloadLen + tagSize), yield);
    deC->decrypt(asio::buffer(buf.data(), n), asio::buffer(out.data(), payloadLen));

    return payloadLen;
}

std::size_t EncryptedConnection::read(asio::mutable_buffer buffer, asio::yield_context yield) {
    readSalt(conn, deC, yield);

    if (remaining > 0) {
        std::size_t n = asio::buffer_copy(buffer, asio::buffer(buf.data() + index, remaining));
        index += n;
        remaining -= n;

        return n;
    }

    try {
        std::size_t payloadSize = readEncryptedPayload(conn, deC, asio::buffer(buf), yield);
        std::size_t n = asio::buffer_copy(buffer, asio::buffer(buf.data(), payloadSize));

        index += n;
        remaining = payloadSize - n;

        return n;
    } catch (const AEAD::DecryptionError& e) {
        log(WARN) << e.what() << '\n';
    }

    return 0;
}

static void writeSalt(Writer& w, const std::unique_ptr<AEAD>& enC, asio::yield_context yield) {
    if (enC->salt()) {
        return;
    }

    static CryptoPP::RandomPool rand;
    std::size_t saltSize = enC->saltSize();
    std::vector<std::uint8_t> salt(saltSize);

    rand.GenerateBlock(salt.data(), saltSize);
    enC->setSalt(asio::buffer(salt));
    w.write(asio::buffer(salt), yield);
}

static std::size_t writeUnencryptedPayload(Writer& w, const std::unique_ptr<AEAD>& enC,
                                           asio::const_buffer in, asio::yield_context yield) {
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
        w.write(asio::buffer(buf.data(), 2 + tagSize), yield);

        // write encrypted payload
        enC->encrypt(asio::buffer(data + nWrite, payloadLen),
                     asio::buffer(buf.data(), payloadLen + tagSize));
        w.write(asio::buffer(buf.data(), payloadLen + tagSize), yield);

        nWrite += payloadLen;
        remaining -= payloadLen;
    }

    return nWrite;
}

std::size_t EncryptedConnection::write(asio::const_buffer buffer, asio::yield_context yield) {
    writeSalt(conn, enC, yield);
    return writeUnencryptedPayload(conn, enC, buffer, yield);
}

void EncryptedConnection::close() {
    conn.close();
}
