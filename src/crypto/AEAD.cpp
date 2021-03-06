#include <cstring>
#include <unordered_map>
#include <vector>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/hkdf.h>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>

#include "AEAD.h"
#include "ChaCha20Poly1305.h"
#include "GCM.h"

// This method is not a member function,
// because there is a problem of mutual inclusion.
template <bool IsEncryption>
static std::unique_ptr<AEAD> create(AEAD::Method method, ConstBytesView key) {
    switch (method) {
    case AEAD::ChaCha20Poly1305:
        return std::make_unique<ChaCha20Poly1305Base<IsEncryption>>(key);
    case AEAD::AES128GCM:
        return std::make_unique<AES128GCMBase<IsEncryption>>(key);
    case AEAD::AES256GCM:
        return std::make_unique<AES256GCMBase<IsEncryption>>(key);
    default:
        break;
    }

    return {};
}

Size AEAD::getKeySize(Method method) {
    static std::unordered_map<Method, Size> keySizes{
        {ChaCha20Poly1305, ChaCha20Poly1305::KeySize},
        {AES128GCM, AES128GCM::KeySize},
        {AES256GCM, AES256GCM::KeySize},
    };

    return keySizes[method];
}

AEAD::Ciphers AEAD::makeCiphers(Method method, ConstBytesView key) {
    return {create<true>(method, key), create<false>(method, key)};
}

void increment(BytesView num) {
    Size len = num.size();

    for (Size i = 0; i != len; i++) {
        num[i]++;
        if (num[i] != 0) {
            break;
        }
    }
}

void deriveKey(ConstBytesView password, BytesView key) {
    CryptoPP::Weak1::MD5 md5;

    Size keySize = key.size();
    std::vector<Byte> buf(keySize);
    Byte* pBuf = buf.data();
    const Byte* pPassword = password.data();

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

    std::memcpy(key.data(), pBuf, keySize);
}

void hkdfSha1(BytesView key, BytesView salt, BytesView subkey) {
    CryptoPP::HKDF<CryptoPP::SHA1> hkdf;
    hkdf.DeriveKey(subkey.data(), subkey.size(),
                   key.data(), key.size(),
                   salt.data(), salt.size(),
                   reinterpret_cast<const Byte*>(AEAD::Info.data()), AEAD::Info.size());
}
