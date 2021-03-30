#include <algorithm>

#include <asio/ts/buffer.hpp>
#include <spdlog/spdlog.h>

#include "ChaCha20Poly1305.h"
#include "EncryptedConnection.h"
#include "GCM.h"

EncryptedConnection::EncryptedConnection(TCPSocket s, AEAD::Ciphers ciphers)
    : EncryptedConnection(std::move(s), std::move(ciphers.first), std::move(ciphers.second)) {}

EncryptedConnection::EncryptedConnection(TCPSocket s, AEADPtr eC, AEADPtr dC)
    : conn(std::move(s)), enC(std::move(eC)), deC(std::move(dC)) {}

asio::awaitable<Size> EncryptedConnection::read(BytesView buffer) {
    co_await readSalt(conn, deC);

    if (remaining > 0) {
        Size n = std::min(remaining, buffer.size());
        std::copy_n(buf.begin() + index, n, buffer.begin());

        index += n;
        remaining -= n;

        co_return n;
    }

    Size payloadSize = co_await readEncryptedPayload(conn, deC, buf);
    Size n = std::min(payloadSize, buffer.size());
    std::copy_n(buf.begin(), n, buffer.begin());

    index += n;
    remaining = payloadSize - n;

    co_return n;
}

asio::awaitable<Size> EncryptedConnection::write(BytesView buffer) {
    co_await writeSalt(conn, enC);
    Size size = co_await writeUnencryptedPayload(conn, enC, buffer);

    co_return size;
}

void EncryptedConnection::close() {
    conn.close();
}
