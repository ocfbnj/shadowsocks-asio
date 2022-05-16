#ifndef ENCRYPTED_CONNECTION_H
#define ENCRYPTED_CONNECTION_H

#include <array>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

#include <crypto/aead.h>

#include "connection.h"

// encrypted_connection decrypts the data after receiving it,
// and encrypts the data before sending it.
class encrypted_connection {
public:
    class duplicate_salt : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    encrypted_connection(tcp_socket s, crypto::aead::method method, std::span<const std::uint8_t> key);

    asio::awaitable<std::size_t> read(std::span<std::uint8_t> buffer);
    asio::awaitable<std::size_t> write(std::span<const std::uint8_t> buffer);

    void close();

    void set_read_timeout(int val);
    void set_connection_timeout(int val);

    asio::ip::tcp::endpoint local_endpoint() const;
    asio::ip::tcp::endpoint remote_endpoint() const;

private:
    static constexpr std::size_t maximum_payload_size = 0x3FFF;
    static constexpr std::size_t maximum_tag_size = 16;
    static constexpr std::size_t maximum_message_size = 2 + maximum_payload_size + 2 * maximum_tag_size;
    static constexpr std::size_t nonce_size = 12;

    std::size_t salt_size() const;

    void encrypt(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> ciphertext);
    void decrypt(std::span<const std::uint8_t> ciphertext, std::span<std::uint8_t> plaintext);

    asio::awaitable<std::size_t> read_encrypted_payload(std::span<std::uint8_t> out);
    asio::awaitable<std::size_t> write_unencrypted_payload(std::span<const std::uint8_t> in);

    // connection is not inherited because we want to use its methods directly.
    connection conn;

    crypto::aead cipher;
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> enc_nonce;
    std::vector<std::uint8_t> dec_nonce;
    std::vector<std::uint8_t> in_salt;
    std::vector<std::uint8_t> out_salt;

    // When the buffer for calling the read function is too small, temporarily put it in buf.
    std::array<std::uint8_t, maximum_message_size> buf;
    std::size_t index = 0;
    std::size_t remaining = 0;
};

#endif
