#include <cstring>
#include <vector>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include "AEAD.h"

void increment(BytesView num) {
    Size len = num.size();

    for (Size i = 0; i != len; i++) {
        num[i]++;
        if (num[i] != 0) {
            break;
        }
    }
}

void deriveKey(BytesView password, Size keySize, BytesView key) {
    CryptoPP::Weak1::MD5 md5;

    std::vector<u8> buf(keySize);
    u8* pBuf = buf.data();
    u8* pPassword = password.data();

    Size passwordSize = password.size();
    Size md5DigestSize = md5.DigestSize();
    Size currentSize = 0;

    while (currentSize < keySize) {
        md5.Update(pBuf, currentSize);
        md5.Update(pPassword, passwordSize);

        if (keySize - currentSize < md5DigestSize) {
            md5.TruncatedFinal(pBuf + currentSize, keySize - currentSize);
            currentSize += keySize - currentSize;
        } else {
            md5.Final(pBuf + currentSize);
            currentSize += md5DigestSize;
        }
    }

    std::memcpy(std::data(key), pBuf, keySize);
}
