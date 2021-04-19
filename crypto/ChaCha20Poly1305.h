#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <cryptopp/chachapoly.h>

#include "AEAD.h"

template <bool IsEncryption>
class ChaCha20Poly1305Base;

class ChaCha20Poly1305 {
public:
    using Encryption = ChaCha20Poly1305Base<true>;
    using Decryption = ChaCha20Poly1305Base<false>;

    static constexpr auto KeySize = 32;
    static constexpr auto SaltSize = 32;
    static constexpr auto NonceSize = 12;
    static constexpr auto TagSize = 16;
};

template <bool IsEncryption>
class ChaCha20Poly1305Base
    : public AEADBase<CryptoPP::ChaCha20Poly1305_Final<IsEncryption>,
                      ChaCha20Poly1305::KeySize,
                      ChaCha20Poly1305::SaltSize,
                      ChaCha20Poly1305::NonceSize,
                      ChaCha20Poly1305::TagSize> {
public:
    using AEADBase<CryptoPP::ChaCha20Poly1305_Final<IsEncryption>,
                   ChaCha20Poly1305::KeySize,
                   ChaCha20Poly1305::SaltSize,
                   ChaCha20Poly1305::NonceSize,
                   ChaCha20Poly1305::TagSize>::AEADBase;
};

#endif
