#include <array>
#include <memory>

#include <gtest/gtest.h>

#include <crypto/AEAD.h>
#include <crypto/ChaCha20Poly1305.h>
#include <crypto/GCM.h>

#include "type.h"

TEST(increment, num0) {
    std::array<Byte, 2> num{0, 0};
    std::array<Byte, 2> expectNum{1, 0};

    increment(num);
    EXPECT_EQ(num, expectNum);
}

TEST(increment, num1) {
    std::array<Byte, 2> num{1, 0};
    std::array<Byte, 2> expectNum{2, 0};

    increment(num);
    EXPECT_EQ(num, expectNum);
}

TEST(increment, num255) {
    std::array<Byte, 2> num{255, 0};
    std::array<Byte, 2> expectNum{0, 1};

    increment(num);
    EXPECT_EQ(num, expectNum);
}

TEST(increment, num256) {
    std::array<Byte, 2> num{0, 1};
    std::array<Byte, 2> expectNum{1, 1};

    increment(num);
    EXPECT_EQ(num, expectNum);
}

TEST(hkdfSha1, key128) {
    std::array<Byte, 16> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<Byte, 16> salt{'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    std::array<Byte, 16> subkey;
    std::array<Byte, 16> expectSubkey{176, 72, 135, 140, 255, 57, 14, 7, 193, 98, 58, 118, 112, 42, 119, 97};

    hkdfSha1(key, salt, subkey);
    EXPECT_EQ(subkey, expectSubkey);
}

TEST(hkdfSha1, key256) {
    std::array<Byte, 32> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<Byte, 32> salt{'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8',
                              '1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
    std::array<Byte, 32> subkey;
    std::array<Byte, 32> expectSubkey{128, 145, 113, 44, 108, 52, 99, 117, 243, 229, 199, 245, 55, 99, 251, 53,
                                      56, 225, 92, 92, 5, 94, 252, 21, 4, 211, 164, 43, 251, 44, 61, 208};

    hkdfSha1(key, salt, subkey);
    EXPECT_EQ(subkey, expectSubkey);
}

TEST(deriveKey, key128) {
    std::array<Byte, 4> password{'h', 'e', 'h', 'e'};
    std::array<Byte, 16> key;
    std::array<Byte, 16> expectKey{82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136, 182, 52, 104, 130, 106};

    deriveKey(password, key);
    EXPECT_EQ(key, expectKey);
}

TEST(deriveKey, key256) {
    std::array<Byte, 4> password{'h', 'e', 'h', 'e'};
    std::array<Byte, 32> key;
    std::array<Byte, 32> expectKey{82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136, 182, 52, 104, 130, 106,
                                   109, 81, 225, 207, 24, 87, 148, 16, 101, 57, 172, 239, 219, 100, 183, 95};

    deriveKey(password, key);
    EXPECT_EQ(key, expectKey);
}

TEST(ChaCha20Poly1305, encrypt) {
    std::array<Byte, ChaCha20Poly1305::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<Byte, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<Byte, 5 + ChaCha20Poly1305::TagSize> ciphertext;
    std::array<Byte, 5 + ChaCha20Poly1305::TagSize> expectCiphertext{
        105, 66, 33, 189, 129, 203, 219, 231, 140, 85, 21,
        136, 140, 75, 200, 219, 165, 104, 17, 161, 79};
    std::unique_ptr<AEAD> enC = std::make_unique<ChaCha20Poly1305::Encryption>(key);

    enC->encrypt(message, ciphertext);
    EXPECT_EQ(ciphertext, expectCiphertext);
}

TEST(ChaCha20Poly1305, decrypt) {
    std::array<Byte, ChaCha20Poly1305::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<Byte, 5 + ChaCha20Poly1305::TagSize> ciphertext{
        105, 66, 33, 189, 129, 203, 219, 231, 140, 85, 21,
        136, 140, 75, 200, 219, 165, 104, 17, 161, 79};
    std::array<Byte, 5> message;
    std::array<Byte, 5> expectMessage{'h', 'e', 'l', 'l', 'o'};
    std::unique_ptr<AEAD> deC = std::make_unique<ChaCha20Poly1305::Decryption>(key);

    deC->decrypt(ciphertext, message);
    EXPECT_EQ(message, expectMessage);
}

TEST(AES128GCM, encrypt) {
    std::array<Byte, AES128GCM::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<Byte, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<Byte, 5 + AES128GCM::TagSize> ciphertext;
    std::array<Byte, 5 + AES128GCM::TagSize> expectCiphertext{
        155, 81, 62, 31, 73, 81, 203, 33, 80, 20, 82,
        166, 186, 215, 189, 136, 234, 215, 88, 8, 172};
    std::unique_ptr<AEAD> enC = std::make_unique<AES128GCM::Encryption>(key);

    enC->encrypt(message, ciphertext);
    EXPECT_EQ(ciphertext, expectCiphertext);
}

TEST(AES128GCM, decrypt) {
    std::array<Byte, AES128GCM::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<Byte, 5 + AES128GCM::TagSize> ciphertext{
        155, 81, 62, 31, 73, 81, 203, 33, 80, 20, 82,
        166, 186, 215, 189, 136, 234, 215, 88, 8, 172};
    std::array<Byte, 5> message;
    std::array<Byte, 5> expectMessage{'h', 'e', 'l', 'l', 'o'};
    std::unique_ptr<AEAD> deC = std::make_unique<AES128GCM::Decryption>(key);

    deC->decrypt(ciphertext, message);
    EXPECT_EQ(message, expectMessage);
}

TEST(AES256GCM, encrypt) {
    std::array<Byte, AES256GCM::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<Byte, 5> message{'h', 'e', 'l', 'l', 'o'};
    std::array<Byte, 5 + AES256GCM::TagSize> ciphertext;
    std::array<Byte, 5 + AES256GCM::TagSize> expectCiphertext{
        215, 80, 244, 176, 26, 211, 81, 171, 33, 189, 255,
        36, 184, 218, 230, 78, 146, 114, 221, 155, 24};
    std::unique_ptr<AEAD> enC = std::make_unique<AES256GCM::Encryption>(key);

    enC->encrypt(message, ciphertext);

    EXPECT_EQ(ciphertext, expectCiphertext);
}

TEST(AES256GCM, decrypt) {
    std::array<Byte, AES256GCM::KeySize> key{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    std::array<Byte, 5 + AES256GCM::TagSize> ciphertext{
        215, 80, 244, 176, 26, 211, 81, 171, 33, 189, 255,
        36, 184, 218, 230, 78, 146, 114, 221, 155, 24};
    std::array<Byte, 5> message;
    std::array<Byte, 5> expectMessage{'h', 'e', 'l', 'l', 'o'};
    std::unique_ptr<AEAD> deC = std::make_unique<AES256GCM::Decryption>(key);

    deC->decrypt(ciphertext, message);
    EXPECT_EQ(message, expectMessage);
}
