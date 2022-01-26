#include <algorithm>
#include <cassert>

#include <crypto/crypto.h>

#include "EncryptedConnection.h"
#include "ReplayProtection.h"
#include "io.h"

EncryptedConnection::EncryptedConnection(TCPSocket s, crypto::AEAD::Method method, std::span<const std::uint8_t> key)
    : conn(std::move(s)),
      cipher(method),
      key(crypto::AEAD::keySize(method)),
      encNonce(NonceSize, 0),
      decNonce(NonceSize, 0) {
    assert(key.size() == this->key.size());
    std::copy(key.begin(), key.end(), this->key.begin());
}

asio::awaitable<std::size_t> EncryptedConnection::read(std::span<std::uint8_t> buffer) {
    bool checkReplayAttack = false;

    // read salt
    if (inSalt.empty()) {
        inSalt.resize(saltSize());
        co_await readFull(conn, inSalt);

        // need to check replay attack
        checkReplayAttack = true;
    }

    if (remaining > 0) {
        std::size_t n = std::min(remaining, buffer.size());
        std::copy_n(buf.begin() + index, n, buffer.begin());

        index += n;
        remaining -= n;

        co_return n;
    }

    std::size_t payloadSize = co_await readEncryptedPayload(buf);

    // check replay attack
    if (checkReplayAttack) {
        auto& protection = ReplayProtection::get();
        if (protection.contains(inSalt)) {
            throw DuplicateSalt{"Duplicate salt received. Possible replay attack"};
        } else {
            protection.insert(inSalt);
        }
    }

    std::size_t n = std::min(payloadSize, buffer.size());
    std::copy_n(buf.begin(), n, buffer.begin());

    index += n;
    remaining = payloadSize - n;

    co_return n;
}

asio::awaitable<std::size_t> EncryptedConnection::write(std::span<const std::uint8_t> buffer) {
    // write salt
    if (outSalt.empty()) {
        outSalt.resize(saltSize());
        crypto::randomBytes(outSalt);
        co_await conn.write(outSalt);
    }

    std::size_t size = co_await writeUnencryptedPayload(buffer);

    co_return size;
}

std::size_t EncryptedConnection::saltSize() const {
    switch (cipher.getMethod()) {
    case crypto::AEAD::ChaCha20Poly1305:
    case crypto::AEAD::AES256GCM:
        return 32;
    case crypto::AEAD::AES128GCM:
        return 16;
    default:
        assert(0);
        return 0;
    }
}

void EncryptedConnection::encrypt(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> ciphertext) {
    std::vector<std::uint8_t> subkey(key.size());
    crypto::hkdfSha1(key, outSalt, crypto::toSpan("ss-subkey"), subkey);

    cipher.encrypt(subkey, encNonce, {}, plaintext, ciphertext);
    crypto::increment(encNonce);
}

void EncryptedConnection::decrypt(std::span<const std::uint8_t> ciphertext, std::span<std::uint8_t> plaintext) {
    std::vector<std::uint8_t> subkey(key.size());
    crypto::hkdfSha1(key, inSalt, crypto::toSpan("ss-subkey"), subkey);

    cipher.decrypt(subkey, decNonce, {}, ciphertext, plaintext);
    crypto::increment(decNonce);
}

asio::awaitable<std::size_t> EncryptedConnection::readEncryptedPayload(std::span<std::uint8_t> out) {
    std::size_t tagSize = cipher.getTagSize();
    std::vector<std::uint8_t> buf(MaximumPayloadSize + tagSize);

    // read encrypted length
    std::size_t n = co_await readFull(conn, std::span{buf.data(), 2 + tagSize});

    std::uint16_t payloadLen = 0;
    decrypt(std::span{buf.data(), n}, std::span{reinterpret_cast<std::uint8_t*>(&payloadLen), 2});
    payloadLen = ntohs(payloadLen);

    // read encrypted payload
    n = co_await readFull(conn, std::span{buf.data(), payloadLen + tagSize});
    decrypt(std::span{buf.data(), n}, std::span{out.data(), payloadLen});

    co_return payloadLen;
}

asio::awaitable<std::size_t> EncryptedConnection::writeUnencryptedPayload(std::span<const std::uint8_t> in) {
    std::size_t remaining = in.size();
    std::size_t nWrite = 0;
    std::size_t tagSize = cipher.getTagSize();
    std::vector<std::uint8_t> buf(MaximumPayloadSize + tagSize);

    while (remaining > 0) {
        std::uint16_t payloadLen = static_cast<std::uint16_t>(remaining);
        if (remaining > MaximumPayloadSize) {
            payloadLen = static_cast<std::uint16_t>(MaximumPayloadSize);
        }

        std::uint16_t len = htons(payloadLen);

        // write encrypted length of payload
        encrypt(std::span{reinterpret_cast<std::uint8_t*>(&len), 2},
                std::span{buf.data(), 2 + tagSize});
        co_await conn.write(std::span{buf.data(), 2 + tagSize});

        // write encrypted payload
        encrypt(std::span{std::data(in) + nWrite, payloadLen},
                std::span{buf.data(), payloadLen + tagSize});
        co_await conn.write(std::span{buf.data(), payloadLen + tagSize});

        nWrite += payloadLen;
        remaining -= payloadLen;
    }

    co_return nWrite;
}
