#ifndef GCM_H
#define GCM_H

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

#include "AEAD.h"

template <bool IsEncryption>
class AES128GCMBase;

class AES128GCM {
public:
    using Encryption = AES128GCMBase<true>;
    using Decryption = AES128GCMBase<false>;

    static constexpr auto KeySize = 16;
    static constexpr auto SaltSize = 16;
    static constexpr auto NonceSize = 12;
    static constexpr auto TagSize = 16;
};

template <bool IsEncryption>
class AES128GCMBase
    : public AEADBase<CryptoPP::GCM_Final<CryptoPP::AES, CryptoPP::GCM_2K_Tables, IsEncryption>,
                      AES128GCM::KeySize,
                      AES128GCM::SaltSize,
                      AES128GCM::NonceSize,
                      AES128GCM::TagSize> {
public:
    AES128GCMBase(ConstBytesView key)
        : AEADBase<CryptoPP::GCM_Final<CryptoPP::AES, CryptoPP::GCM_2K_Tables, IsEncryption>,
                   AES128GCM::KeySize,
                   AES128GCM::SaltSize,
                   AES128GCM::NonceSize,
                   AES128GCM::TagSize>(key) {}
};

template <bool IsEncryption>
class AES256GCMBase;

class AES256GCM {
public:
    using Encryption = AES256GCMBase<true>;
    using Decryption = AES256GCMBase<false>;

    static constexpr auto KeySize = 32;
    static constexpr auto SaltSize = 32;
    static constexpr auto NonceSize = 12;
    static constexpr auto TagSize = 16;
};

template <bool IsEncryption>
class AES256GCMBase
    : public AEADBase<CryptoPP::GCM_Final<CryptoPP::AES, CryptoPP::GCM_2K_Tables, IsEncryption>,
                      AES256GCM::KeySize,
                      AES256GCM::SaltSize,
                      AES256GCM::NonceSize,
                      AES256GCM::TagSize> {
public:
    AES256GCMBase(ConstBytesView key)
        : AEADBase<CryptoPP::GCM_Final<CryptoPP::AES, CryptoPP::GCM_2K_Tables, IsEncryption>,
                   AES256GCM::KeySize,
                   AES256GCM::SaltSize,
                   AES256GCM::NonceSize,
                   AES256GCM::TagSize>(key) {}
};

#endif
