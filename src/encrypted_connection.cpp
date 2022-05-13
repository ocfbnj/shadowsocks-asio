#include <algorithm>
#include <cassert>

#include <crypto/crypto.h>

#include "encrypted_connection.h"
#include "io.h"
#include "replay_protection.h"

encrypted_connection::encrypted_connection(tcp_socket s, crypto::aead::method method, std::span<const std::uint8_t> key)
    : conn(std::move(s)),
      cipher(method),
      key(crypto::aead::key_size(method)),
      enc_nonce(nonce_size, 0),
      dec_nonce(nonce_size, 0) {
    assert(key.size() == this->key.size());
    std::copy(key.begin(), key.end(), this->key.begin());
}

asio::awaitable<std::size_t> encrypted_connection::read(std::span<std::uint8_t> buffer) {
    bool check_replay_attack = false;

    // read salt
    if (in_salt.empty()) {
        in_salt.resize(salt_size());
        co_await read_full(conn, in_salt);

        // need to check replay attack
        check_replay_attack = true;
    }

    if (remaining > 0) {
        std::size_t n = std::min(remaining, buffer.size());
        std::copy_n(buf.begin() + index, n, buffer.begin());

        index += n;
        remaining -= n;

        co_return n;
    }

    std::size_t payload_size = co_await read_encrypted_payload(buf);

    // check replay attack
    if (check_replay_attack) {
        auto& protection = replay_protection::get();
        if (protection.contains(in_salt)) {
            throw duplicate_salt{"Duplicate salt received. Possible replay attack"};
        } else {
            protection.insert(in_salt);
        }
    }

    std::size_t n = std::min(payload_size, buffer.size());
    std::copy_n(buf.begin(), n, buffer.begin());

    index += n;
    remaining = payload_size - n;

    co_return n;
}

asio::awaitable<std::size_t> encrypted_connection::write(std::span<const std::uint8_t> buffer) {
    // write salt
    if (out_salt.empty()) {
        out_salt.resize(salt_size());
        crypto::random_bytes(out_salt);
        co_await conn.write(out_salt);
    }

    std::size_t size = co_await write_unencrypted_payload(buffer);

    co_return size;
}

void encrypted_connection::close() {
    conn.close();
}

void encrypted_connection::set_read_timeout(int val) {
    conn.set_read_timeout(val);
}

std::size_t encrypted_connection::salt_size() const {
    switch (cipher.get_method()) {
    case crypto::aead::chacha20_poly1305:
    case crypto::aead::aes_256_gcm:
        return 32;
    case crypto::aead::aes_128_gcm:
        return 16;
    default:
        assert(0);
        return 0;
    }
}

void encrypted_connection::encrypt(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> ciphertext) {
    std::vector<std::uint8_t> subkey(key.size());
    crypto::hkdf_sha1(key, out_salt, crypto::to_span("ss-subkey"), subkey);

    cipher.encrypt(subkey, enc_nonce, {}, plaintext, ciphertext);
    crypto::increment(enc_nonce);
}

void encrypted_connection::decrypt(std::span<const std::uint8_t> ciphertext, std::span<std::uint8_t> plaintext) {
    std::vector<std::uint8_t> subkey(key.size());
    crypto::hkdf_sha1(key, in_salt, crypto::to_span("ss-subkey"), subkey);

    cipher.decrypt(subkey, dec_nonce, {}, ciphertext, plaintext);
    crypto::increment(dec_nonce);
}

asio::awaitable<std::size_t> encrypted_connection::read_encrypted_payload(std::span<std::uint8_t> out) {
    std::size_t tag_size = cipher.get_tag_size();
    std::vector<std::uint8_t> buf(maximum_payload_size + tag_size);

    // read encrypted length
    std::size_t n = co_await read_full(conn, std::span{buf.data(), 2 + tag_size});

    std::uint16_t payload_len = 0;
    decrypt(std::span{buf.data(), n}, std::span{reinterpret_cast<std::uint8_t*>(&payload_len), 2});
    payload_len = ntohs(payload_len);

    // read encrypted payload
    n = co_await read_full(conn, std::span{buf.data(), payload_len + tag_size});
    decrypt(std::span{buf.data(), n}, std::span{out.data(), payload_len});

    co_return payload_len;
}

asio::awaitable<std::size_t> encrypted_connection::write_unencrypted_payload(std::span<const std::uint8_t> in) {
    std::size_t remaining = in.size();
    std::size_t n_write = 0;
    std::size_t tag_size = cipher.get_tag_size();
    std::vector<std::uint8_t> buf(maximum_payload_size + tag_size);

    while (remaining > 0) {
        std::uint16_t payload_len = static_cast<std::uint16_t>(remaining);
        if (remaining > maximum_payload_size) {
            payload_len = static_cast<std::uint16_t>(maximum_payload_size);
        }

        std::uint16_t len = htons(payload_len);

        // write encrypted length of payload
        encrypt(std::span{reinterpret_cast<std::uint8_t*>(&len), 2},
                std::span{buf.data(), 2 + tag_size});
        co_await conn.write(std::span{buf.data(), 2 + tag_size});

        // write encrypted payload
        encrypt(std::span{std::data(in) + n_write, payload_len},
                std::span{buf.data(), payload_len + tag_size});
        co_await conn.write(std::span{buf.data(), payload_len + tag_size});

        n_write += payload_len;
        remaining -= payload_len;
    }

    co_return n_write;
}
