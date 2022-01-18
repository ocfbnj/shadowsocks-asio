#ifndef OCFBNJ_CRYPTO_GCM_H
#define OCFBNJ_CRYPTO_GCM_H

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

#include <crypto/AEAD.h>

template <bool IsEncryption>
class AES128GCMImpl;

class AES128GCM {
public:
    using Encryption = AES128GCMImpl<true>;
    using Decryption = AES128GCMImpl<false>;

    static constexpr auto KeySize = 16;
    static constexpr auto SaltSize = 16;
    static constexpr auto NonceSize = 12;
    static constexpr auto TagSize = 16;
};

template <bool IsEncryption>
class AES128GCMImpl
    : public AEADImpl<CryptoPP::GCM_Final<CryptoPP::AES, CryptoPP::GCM_2K_Tables, IsEncryption>,
                      AES128GCM::KeySize,
                      AES128GCM::SaltSize,
                      AES128GCM::NonceSize,
                      AES128GCM::TagSize> {
public:
    using AEADImpl<CryptoPP::GCM_Final<CryptoPP::AES, CryptoPP::GCM_2K_Tables, IsEncryption>,
                   AES128GCM::KeySize,
                   AES128GCM::SaltSize,
                   AES128GCM::NonceSize,
                   AES128GCM::TagSize>::AEADImpl;
};

template <bool IsEncryption>
class AES256GCMImpl;

class AES256GCM {
public:
    using Encryption = AES256GCMImpl<true>;
    using Decryption = AES256GCMImpl<false>;

    static constexpr auto KeySize = 32;
    static constexpr auto SaltSize = 32;
    static constexpr auto NonceSize = 12;
    static constexpr auto TagSize = 16;
};

template <bool IsEncryption>
class AES256GCMImpl
    : public AEADImpl<CryptoPP::GCM_Final<CryptoPP::AES, CryptoPP::GCM_2K_Tables, IsEncryption>,
                      AES256GCM::KeySize,
                      AES256GCM::SaltSize,
                      AES256GCM::NonceSize,
                      AES256GCM::TagSize> {
public:
    using AEADImpl<CryptoPP::GCM_Final<CryptoPP::AES, CryptoPP::GCM_2K_Tables, IsEncryption>,
                   AES256GCM::KeySize,
                   AES256GCM::SaltSize,
                   AES256GCM::NonceSize,
                   AES256GCM::TagSize>::AEADImpl;
};

#endif
