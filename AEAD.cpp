#include <cstring>
#include <vector>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include "AEAD.h"

void increment(std::span<std::uint8_t> num) {
    std::size_t len = std::size(num);

    for (std::size_t i = 0; i != len; i++) {
        num[i]++;
        if (num[i] != 0) {
            break;
        }
    }
}

void deriveKey(std::span<std::uint8_t> password, std::size_t keySize, std::span<std::uint8_t> key) {
    CryptoPP::Weak1::MD5 md5;
    std::vector<std::uint8_t> buf(keySize);
    std::uint8_t* pBuf = std::data(buf);
    std::uint8_t* pPassword = std::data(password);
    std::size_t passwordLen = std::size(password);
    std::size_t md5DigestSize = md5.DigestSize();
    std::size_t len = 0;

    while (len < keySize) {
        md5.Update(pBuf, len);
        md5.Update(pPassword, passwordLen);

        if (keySize - len < md5DigestSize) {
            md5.TruncatedFinal(pBuf + len, keySize - len);
            len += keySize - len;
        } else {
            md5.Final(pBuf + len);
            len += md5DigestSize;
        }
    }

    std::memcpy(std::data(key), pBuf, keySize);
}
