#ifndef ENCRYPTED_CONNECTION_H
#define ENCRYPTED_CONNECTION_H

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
    EncryptedConnection(TCPSocket s, AEAD::Ciphers ciphers);
    EncryptedConnection(TCPSocket s, AEADPtr eC, AEADPtr dC);

    asio::awaitable<Size> read(BytesView buffer);
    asio::awaitable<Size> write(BytesView buffer);
    void close();

private:
    static constexpr auto MaximumMessageSize = 2 + AEAD::MaximumPayloadSize + 2 * AEAD::MaximumTagSize;

    // Connection is not inherited because we want to use its methods directly.
    Connection conn;

    AEADPtr enC;
    AEADPtr deC;

    // When the buffer for calling the read function is too small, temporarily put it in buf.
    std::array<Byte, MaximumMessageSize> buf;
    Size index = 0;
    Size remaining = 0;
};

asio::awaitable<void> readSalt(Reader auto& r, const AEADPtr& deC) {
    if (deC->salt()) {
        co_return;
    }

    std::vector<Byte> salt(deC->saltSize());
    co_await readFull(r, salt);
    deC->setSalt(salt);
}

asio::awaitable<Size> readEncryptedPayload(Reader auto& r, const AEADPtr& deC, BytesView out) {
    Size tagSize = deC->tagSize();
    std::vector<Byte> buf(AEAD::MaximumPayloadSize + tagSize);

    // read encrypted length
    Size n = co_await readFull(r, BytesView{buf.data(), 2 + tagSize});

    u16 payloadLen = 0;
    deC->decrypt(BytesView{buf.data(), n}, BytesView{reinterpret_cast<Byte*>(&payloadLen), 2});
    payloadLen = ::ntohs(payloadLen);

    // read encrypted payload
    n = co_await readFull(r, BytesView{buf.data(), payloadLen + tagSize});
    deC->decrypt(BytesView{buf.data(), n}, BytesView{out.data(), payloadLen});

    co_return payloadLen;
}

asio::awaitable<void> writeSalt(Writer auto& w, const AEADPtr& enC) {
    if (enC->salt()) {
        co_return;
    }

    static thread_local CryptoPP::RandomPool rand;
    Size saltSize = enC->saltSize();
    std::vector<Byte> salt(saltSize);

    rand.GenerateBlock(salt.data(), saltSize);
    enC->setSalt(salt);
    co_await w.write(salt);
}

asio::awaitable<Size> writeUnencryptedPayload(Writer auto& w, const AEADPtr& enC, BytesView in) {
    Size remaining = in.size();
    Size nWrite = 0;
    Size tagSize = enC->tagSize();
    std::vector<Byte> buf(AEAD::MaximumPayloadSize + tagSize);

    while (remaining > 0) {
        u16 payloadLen = static_cast<u16>(remaining);
        if (remaining > AEAD::MaximumPayloadSize) {
            payloadLen = static_cast<u16>(AEAD::MaximumPayloadSize);
        }

        u16 len = htons(payloadLen);

        // write encrypted length of payload
        enC->encrypt(BytesView{reinterpret_cast<Byte*>(&len), 2},
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
