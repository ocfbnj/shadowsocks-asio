#include "EncryptedConnection.h"
#include "ChaCha20Poly1305.h"
#include "logger.h"

EncryptedConnection::EncryptedConnection(asio::ip::tcp::socket s, asio::const_buffer key)
    : conn(std::move(s)),
      enC(std::make_unique<ChaCha20Poly1305<true>>(key)),
      deC(std::make_unique<ChaCha20Poly1305<false>>(key)) {}

asio::awaitable<std::size_t> EncryptedConnection::read(asio::mutable_buffer buffer) {
    co_await readSalt(conn, deC);

    if (remaining > 0) {
        std::size_t n = asio::buffer_copy(buffer, asio::buffer(buf.data() + index, remaining));
        index += n;
        remaining -= n;

        co_return n;
    }

    try {
        std::size_t payloadSize = co_await readEncryptedPayload(conn, deC, asio::buffer(buf));
        std::size_t n = asio::buffer_copy(buffer, asio::buffer(buf.data(), payloadSize));

        index += n;
        remaining = payloadSize - n;

        co_return n;
    } catch (const AEAD::DecryptionError& e) {
        log(WARN) << e.what() << '\n';
    }

    co_return 0;
}

asio::awaitable<std::size_t> EncryptedConnection::write(asio::const_buffer buffer) {
    co_await writeSalt(conn, enC);
    std::size_t size = co_await writeUnencryptedPayload(conn, enC, buffer);
    co_return size;
}

void EncryptedConnection::close() {
    conn.close();
}
