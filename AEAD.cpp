#include <cstdint>
#include <vector>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include "AEAD.h"

void increment(asio::mutable_buffer num) {
    std::size_t len = num.size();
    std::uint8_t* data = static_cast<std::uint8_t*>(num.data());

    for (std::size_t i = 0; i != len; i++) {
        data[i]++;
        if (data[i] != 0) {
            break;
        }
    }
}

void deriveKey(asio::const_buffer password, std::size_t keySize, asio::mutable_buffer key) {
    CryptoPP::Weak1::MD5 md5;
    std::vector<std::uint8_t> buf(keySize);
    std::size_t len = 0;

    const std::uint8_t* pPassword = static_cast<const std::uint8_t*>(password.data());
    std::size_t passwordLen = password.size();

    while (len < keySize) {
        md5.Update(buf.data(), len);
        md5.Update(pPassword, passwordLen);

        if (buf.size() - len < md5.DigestSize()) {
            md5.TruncatedFinal(buf.data() + len, buf.size() - len);
            len += buf.size() - len;
        } else {
            md5.Final(buf.data() + len);
            len += md5.DigestSize();
        }
    }

    std::memcpy(key.data(), buf.data(), keySize);
}
