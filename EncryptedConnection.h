#ifndef ENCRYPTED_SESSION_H
#define ENCRYPTED_SESSION_H

#include <array>
#include <memory>
#include <span>
#include <vector>

#include <cryptopp/randpool.h>

#include "AEAD.h"
#include "Connection.h"
#include "io.h"
#include "type.h"

// EncryptedConnection decrypts the data after receiving it,
// and encrypts the data before sending it.
class EncryptedConnection {
public:
    EncryptedConnection(TCPSocket s, BytesView key);

    asio::awaitable<Size> read(BytesView buffer);
    asio::awaitable<Size> write(BytesView buffer);
    void close();

private:
    static constexpr auto MaximumMessageSize = 2 + AEAD::MaximumPayloadSize + 2 * AEAD::MaximumTagSize;

    // Connection is not inherited because we want to use its methods directly.
    Connection conn;

    std::unique_ptr<AEAD> enC;
    std::unique_ptr<AEAD> deC;

    // When the buffer for calling the read function is too small, temporarily put it in buf.
    std::array<u8, MaximumMessageSize> buf;
    Size index = 0;
    Size remaining = 0;
};

asio::awaitable<void> readSalt(Reader auto& r, const std::unique_ptr<AEAD>& deC) {
    if (deC->salt()) {
        co_return;
    }

    std::vector<u8> salt(deC->saltSize());
    co_await readFull(r, salt);
    deC->setSalt(salt);
}

asio::awaitable<Size> readEncryptedPayload(Reader auto& r, const std::unique_ptr<AEAD>& deC,
                                           BytesView out) {
    Size tagSize = deC->tagSize();
    std::vector<u8> buf(AEAD::MaximumPayloadSize + tagSize);

    // read encrypted length
    Size n = co_await readFull(r, BytesView{buf.data(), 2 + tagSize});

    u16 payloadLen = 0;
    deC->decrypt(BytesView{buf.data(), n}, BytesView{reinterpret_cast<u8*>(&payloadLen), 2});
    payloadLen = ::ntohs(payloadLen);

    // read encrypted payload
    n = co_await readFull(r, BytesView{buf.data(), payloadLen + tagSize});
    deC->decrypt(BytesView{buf.data(), n}, BytesView{out.data(), payloadLen});

    co_return payloadLen;
}

asio::awaitable<void> writeSalt(Writer auto& w, const std::unique_ptr<AEAD>& enC) {
    if (enC->salt()) {
        co_return;
    }

    static thread_local CryptoPP::RandomPool rand;
    Size saltSize = enC->saltSize();
    std::vector<u8> salt(saltSize);

    rand.GenerateBlock(salt.data(), saltSize);
    enC->setSalt(salt);
    co_await w.write(salt);
}

asio::awaitable<Size> writeUnencryptedPayload(Writer auto& w, const std::unique_ptr<AEAD>& enC,
                                              BytesView in) {
    Size remaining = in.size();
    Size nWrite = 0;
    Size tagSize = enC->tagSize();
    std::vector<u8> buf(AEAD::MaximumPayloadSize + tagSize);

    while (remaining > 0) {
        u16 payloadLen = static_cast<u16>(remaining);
        if (remaining > AEAD::MaximumPayloadSize) {
            payloadLen = static_cast<u16>(AEAD::MaximumPayloadSize);
        }

        u16 len = htons(payloadLen);

        // write encrypted length of payload
        enC->encrypt(BytesView{reinterpret_cast<u8*>(&len), 2},
                     BytesView{buf.data(), 2 + tagSize});
        co_await w.write(BytesView{buf.data(), 2 + tagSize});

        // write encrypted payload
        enC->encrypt(BytesView{std::data(in) + nWrite, payloadLen},
                     BytesView{buf.data(), payloadLen + tagSize});
        co_await w.write(BytesView{buf.data(), payloadLen + tagSize});

        nWrite += payloadLen;
        remaining -= payloadLen;
    }

    co_return nWrite;
}

#endif
