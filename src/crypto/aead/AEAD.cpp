#include <cassert>
#include <cstdlib>

#include <mbedtls/cipher.h>

#include <crypto/aead/AEAD.h>

namespace crypto {
inline namespace aead {
AEAD::AEAD(Method method) : method(method) {
    ptr = malloc(sizeof(mbedtls_cipher_context_t));
    assert(ptr != nullptr);
    memset(ptr, 0, sizeof(mbedtls_cipher_context_t));

    auto ctx = static_cast<mbedtls_cipher_context_t*>(ptr);

    mbedtls_cipher_init(ctx);

    mbedtls_cipher_type_t cipherType;
    switch (method) {
    case ChaCha20Poly1305:
        cipherType = MBEDTLS_CIPHER_CHACHA20_POLY1305;
        break;
    case AES128GCM:
        cipherType = MBEDTLS_CIPHER_AES_128_GCM;
        break;
    case AES256GCM:
        cipherType = MBEDTLS_CIPHER_AES_256_GCM;
        break;
    default:
        assert(0);
        break;
    }

    const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(cipherType);
    int ret = mbedtls_cipher_setup(ctx, info);
    assert(ret == 0);
}

AEAD::~AEAD() {
    auto ctx = static_cast<mbedtls_cipher_context_t*>(ptr);
    assert(ctx != nullptr);

    mbedtls_cipher_free(ctx);
    free(ctx);
}

std::size_t AEAD::encrypt(std::span<const std::uint8_t> key,
                          std::span<const std::uint8_t> iv,
                          std::span<const std::uint8_t> ad,
                          std::span<const std::uint8_t> plaintext,
                          std::span<std::uint8_t> ciphertext) {
    assert(key.size() == keySize(method));
    assert(iv.size() == ivSize(method));
    assert(ciphertext.size() == plaintext.size() + tagSize(method));

    auto ctx = static_cast<mbedtls_cipher_context_t*>(ptr);
    assert(ctx != nullptr);

    int ret = mbedtls_cipher_setkey(ctx, key.data(), key.size() * 8, MBEDTLS_ENCRYPT);
    assert(ret == 0);

    std::size_t olen = 0;
    ret = mbedtls_cipher_auth_encrypt_ext(ctx,
                                          iv.data(), iv.size(),
                                          ad.data(), ad.size(),
                                          plaintext.data(), plaintext.size(),
                                          ciphertext.data(), ciphertext.size(),
                                          &olen,
                                          tagSize(method));
    assert(ret == 0);

    return olen;
}

std::size_t AEAD::decrypt(std::span<const std::uint8_t> key,
                          std::span<const std::uint8_t> iv,
                          std::span<const std::uint8_t> ad,
                          std::span<const std::uint8_t> ciphertext,
                          std::span<std::uint8_t> plaintext) {
    assert(key.size() == keySize(method));
    assert(iv.size() == ivSize(method));
    assert(ciphertext.size() == plaintext.size() + tagSize(method));

    auto ctx = static_cast<mbedtls_cipher_context_t*>(ptr);
    assert(ctx != nullptr);

    int ret = mbedtls_cipher_setkey(ctx, key.data(), key.size() * 8, MBEDTLS_DECRYPT);
    assert(ret == 0);

    std::size_t olen = 0;
    ret = mbedtls_cipher_auth_decrypt_ext(ctx,
                                          iv.data(), iv.size(),
                                          ad.data(), ad.size(),
                                          ciphertext.data(), ciphertext.size(),
                                          plaintext.data(), plaintext.size(),
                                          &olen,
                                          tagSize(method));
    if (ret != 0) {
        throw DecryptionError{"decryption error"};
    }

    return olen;
}

std::size_t AEAD::getKeySize() const {
    return keySize(method);
}

std::size_t AEAD::getIvSize() const {
    return ivSize(method);
}

std::size_t AEAD::getTagSize() const {
    return tagSize(method);
}

AEAD::Method AEAD::getMethod() const {
    return method;
}
} // namespace aead
} // namespace crypto
