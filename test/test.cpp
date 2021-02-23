#include <iostream>
#include <memory>

#include <gtest/gtest.h>

#include "../AEAD.h"
#include "../ChaCha20Poly1305.h"

GTEST_TEST(increment, num0) {
    CryptoPP::byte num[2] = {0, 0};
    CryptoPP::byte expectNum[2] = {1, 0};
    increment(asio::buffer(num));
    ASSERT_TRUE(std::memcmp(num, expectNum, 2) == 0);
}

GTEST_TEST(increment, num1) {
    CryptoPP::byte num[2] = {1, 0};
    CryptoPP::byte expectNum[2] = {2, 0};
    increment(asio::buffer(num));
    ASSERT_TRUE(std::memcmp(num, expectNum, 2) == 0);
}

GTEST_TEST(increment, num255) {
    CryptoPP::byte num[2] = {255, 0};
    CryptoPP::byte expectNum[2] = {0, 1};
    increment(asio::buffer(num));
    ASSERT_TRUE(std::memcmp(num, expectNum, 2) == 0);
}

GTEST_TEST(increment, num256) {
    CryptoPP::byte num[2] = {0, 1};
    CryptoPP::byte expectNum[2] = {1, 1};
    increment(asio::buffer(num));
    ASSERT_TRUE(std::memcmp(num, expectNum, 2) == 0);
}

GTEST_TEST(ChaCha20Poly1305, deriveKey) {
    CryptoPP::byte password[4] = {'h', 'e', 'h', 'e'};
    CryptoPP::byte key[ChaCha20Poly1305<>::KeySize];
    CryptoPP::byte expectKey[ChaCha20Poly1305<>::KeySize] = {
        82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136, 182, 52, 104, 130, 106,
        109, 81, 225, 207, 24, 87, 148, 16, 101, 57, 172, 239, 219, 100, 183, 95};

    deriveKey(asio::buffer(password), ChaCha20Poly1305<>::KeySize, asio::buffer(key));

    ASSERT_TRUE(std::memcmp(key, expectKey, ChaCha20Poly1305<>::KeySize) == 0);
}

GTEST_TEST(ChaCha20Poly1305, encrypt) {
    CryptoPP::byte key[ChaCha20Poly1305<>::KeySize] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    CryptoPP::byte message[5] = {'h', 'e', 'l', 'l', 'o'};
    CryptoPP::byte ciphertext[5 + ChaCha20Poly1305<>::TagSize];
    CryptoPP::byte expectCiphertext[5 + ChaCha20Poly1305<>::TagSize] = {
        105, 66, 33, 189, 129, 203, 219, 231, 140, 85, 21,
        136, 140, 75, 200, 219, 165, 104, 17, 161, 79};

    std::unique_ptr<AEAD> enC = std::make_unique<ChaCha20Poly1305<true>>(asio::buffer(key));
    enC->encrypt(asio::buffer(message, 5), asio::buffer(ciphertext));

    ASSERT_TRUE(std::memcmp(ciphertext, expectCiphertext, 5 + ChaCha20Poly1305<>::TagSize) == 0);
}

GTEST_TEST(ChaCha20Poly1305, decrypt) {
    CryptoPP::byte key[ChaCha20Poly1305<>::KeySize] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    CryptoPP::byte ciphertext[5 + ChaCha20Poly1305<>::TagSize] = {105, 66, 33, 189, 129, 203, 219,
                                                                  231, 140, 85, 21, 136, 140, 75,
                                                                  200, 219, 165, 104, 17, 161, 79};
    CryptoPP::byte message[5];
    CryptoPP::byte expectMessage[5] = {'h', 'e', 'l', 'l', 'o'};

    std::unique_ptr<AEAD> deC = std::make_unique<ChaCha20Poly1305<false>>(asio::buffer(key));
    deC->decrypt(asio::buffer(ciphertext), asio::buffer(message));

    ASSERT_TRUE(std::memcmp(message, expectMessage, 5) == 0);
}

GTEST_TEST(ChaCha20Poly1305, HKDFSHA1) {
    CryptoPP::byte key[ChaCha20Poly1305<>::KeySize] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                       1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    CryptoPP::byte salt[ChaCha20Poly1305<>::SaltSize] = {
        '1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8',
        '1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    CryptoPP::byte subkey[ChaCha20Poly1305<>::KeySize];
    CryptoPP::byte expectSubkey[ChaCha20Poly1305<>::KeySize] = {
        128, 145, 113, 44, 108, 52, 99, 117, 243, 229, 199, 245, 55, 99, 251, 53,
        56, 225, 92, 92, 5, 94, 252, 21, 4, 211, 164, 43, 251, 44, 61, 208};

    ChaCha20Poly1305<>::HKDFSHA1(asio::buffer(key), asio::buffer(salt), asio::buffer(subkey));

    ASSERT_TRUE(std::memcmp(subkey, expectSubkey, ChaCha20Poly1305<>::KeySize) == 0);
}
