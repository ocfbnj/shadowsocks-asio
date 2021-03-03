#include <cstddef>
#include <iostream>
#include <memory>

#include <gtest/gtest.h>

#include "../AEAD.h"
#include "../ChaCha20Poly1305.h"

GTEST_TEST(increment, num0) {
    std::uint8_t num[2] = {0, 0};
    std::uint8_t expectNum[2] = {1, 0};
    increment(num);
    ASSERT_TRUE(std::memcmp(num, expectNum, 2) == 0);
}

GTEST_TEST(increment, num1) {
    std::uint8_t num[2] = {1, 0};
    std::uint8_t expectNum[2] = {2, 0};
    increment(num);
    ASSERT_TRUE(std::memcmp(num, expectNum, 2) == 0);
}

GTEST_TEST(increment, num255) {
    std::uint8_t num[2] = {255, 0};
    std::uint8_t expectNum[2] = {0, 1};
    increment(num);
    ASSERT_TRUE(std::memcmp(num, expectNum, 2) == 0);
}

GTEST_TEST(increment, num256) {
    std::uint8_t num[2] = {0, 1};
    std::uint8_t expectNum[2] = {1, 1};
    increment(num);
    ASSERT_TRUE(std::memcmp(num, expectNum, 2) == 0);
}

GTEST_TEST(ChaCha20Poly1305, deriveKey) {
    std::uint8_t password[4] = {'h', 'e', 'h', 'e'};
    std::uint8_t key[ChaCha20Poly1305<>::KeySize];
    std::uint8_t expectKey[ChaCha20Poly1305<>::KeySize] = {
        82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136, 182, 52, 104, 130, 106,
        109, 81, 225, 207, 24, 87, 148, 16, 101, 57, 172, 239, 219, 100, 183, 95};

    deriveKey(password, ChaCha20Poly1305<>::KeySize, key);

    ASSERT_TRUE(std::memcmp(key, expectKey, ChaCha20Poly1305<>::KeySize) == 0);
}

GTEST_TEST(ChaCha20Poly1305, encrypt) {
    std::uint8_t key[ChaCha20Poly1305<>::KeySize] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::uint8_t message[5] = {'h', 'e', 'l', 'l', 'o'};
    std::uint8_t ciphertext[5 + ChaCha20Poly1305<>::TagSize];
    std::uint8_t expectCiphertext[5 + ChaCha20Poly1305<>::TagSize] = {
        105, 66, 33, 189, 129, 203, 219, 231, 140, 85, 21,
        136, 140, 75, 200, 219, 165, 104, 17, 161, 79};

    std::unique_ptr<AEAD> enC = std::make_unique<ChaCha20Poly1305<true>>(key);
    enC->encrypt(message, ciphertext);

    ASSERT_TRUE(std::memcmp(ciphertext, expectCiphertext, 5 + ChaCha20Poly1305<>::TagSize) == 0);
}

GTEST_TEST(ChaCha20Poly1305, decrypt) {
    std::uint8_t key[ChaCha20Poly1305<>::KeySize] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::uint8_t ciphertext[5 + ChaCha20Poly1305<>::TagSize] = {105, 66, 33, 189, 129, 203, 219,
                                                                231, 140, 85, 21, 136, 140, 75,
                                                                200, 219, 165, 104, 17, 161, 79};
    std::uint8_t message[5];
    std::uint8_t expectMessage[5] = {'h', 'e', 'l', 'l', 'o'};

    std::unique_ptr<AEAD> deC = std::make_unique<ChaCha20Poly1305<false>>(key);
    deC->decrypt(ciphertext, message);

    ASSERT_TRUE(std::memcmp(message, expectMessage, 5) == 0);
}

GTEST_TEST(ChaCha20Poly1305, HKDFSHA1) {
    std::uint8_t key[ChaCha20Poly1305<>::KeySize] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::uint8_t salt[ChaCha20Poly1305<>::SaltSize] = {
        '1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8',
        '1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    std::uint8_t subkey[ChaCha20Poly1305<>::KeySize];
    std::uint8_t expectSubkey[ChaCha20Poly1305<>::KeySize] = {
        128, 145, 113, 44, 108, 52, 99, 117, 243, 229, 199, 245, 55, 99, 251, 53,
        56, 225, 92, 92, 5, 94, 252, 21, 4, 211, 164, 43, 251, 44, 61, 208};

    ChaCha20Poly1305<>::HKDFSHA1(key, salt, subkey);

    ASSERT_TRUE(std::memcmp(subkey, expectSubkey, ChaCha20Poly1305<>::KeySize) == 0);
}
