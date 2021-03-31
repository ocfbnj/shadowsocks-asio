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

Size AEAD::getKeySize(Cipher type) {
    static std::unordered_map<Cipher, Size> keySizes{
        {ChaCha20Poly1305, ChaCha20Poly1305::KeySize},
        {AES256GCM, AES256GCM::KeySize},
        {AES128GCM, AES128GCM::KeySize},
    };

    return keySizes[type];
}

AEAD::Ciphers AEAD::makeCiphers(Cipher type, ConstBytesView password) {
    // TODO deriveKey only needs to be called once

    std::array<Byte, MaximumKeySize> key;
    deriveKey(ConstBytesView{password.data(), password.size()}, BytesView{key.data(), getKeySize(type)});

    return {create<true>(type, key), create<false>(type, key)};
}

AEAD::Ciphers AEAD::makeCiphers(AEAD::Cipher type, std::string_view password) {
    return makeCiphers(type, ConstBytesView{reinterpret_cast<const Byte*>(password.data()), password.size()});
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
                   reinterpret_cast<const u8*>(AEAD::Info.data()), AEAD::Info.size());
}
