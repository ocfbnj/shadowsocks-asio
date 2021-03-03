#include <algorithm>
#include <iterator>

#include <asio/ts/buffer.hpp>

#include "ChaCha20Poly1305.h"
#include "EncryptedConnection.h"
#include "logger.h"

EncryptedConnection::EncryptedConnection(asio::ip::tcp::socket s, std::span<std::uint8_t> key)
    : conn(std::move(s)),
      enC(std::make_unique<ChaCha20Poly1305<true>>(key)),
      deC(std::make_unique<ChaCha20Poly1305<false>>(key)) {}

asio::awaitable<std::size_t> EncryptedConnection::read(std::span<std::uint8_t> buffer) {
    co_await readSalt(conn, deC);

    if (remaining > 0) {
        std::size_t n = std::min(remaining, std::size(buffer));
        std::copy_n(std::next(std::begin(buf), index), n, std::begin(buffer));

        index += n;
        remaining -= n;

        co_return n;
    }

    try {
        std::size_t payloadSize = co_await readEncryptedPayload(conn, deC, buf);
        std::size_t n = std::min(payloadSize, std::size(buffer));
        std::copy_n(std::begin(buf), n, std::begin(buffer));

        index += n;
        remaining = payloadSize - n;

        co_return n;
    } catch (const AEAD::DecryptionError& e) {
        log(WARN) << e.what() << '\n';
    }

    co_return 0;
}

asio::awaitable<std::size_t> EncryptedConnection::write(std::span<std::uint8_t> buffer) {
    co_await writeSalt(conn, enC);
    std::size_t size = co_await writeUnencryptedPayload(conn, enC, buffer);
    co_return size;
}

void EncryptedConnection::close() {
    conn.close();
}
