#include <cstring>
#include <unordered_map>
#include <vector>

#include <crypto/AEAD.h>
#include <crypto/ChaCha20Poly1305.h>
#include <crypto/GCM.h>

namespace {
// This method is not a member function,
// because there is a problem of mutual inclusion.
template <bool IsEncryption>
std::unique_ptr<AEAD> create(AEAD::Method method, ConstBytesView key) {
    switch (method) {
    case AEAD::ChaCha20Poly1305:
        return std::make_unique<ChaCha20Poly1305Impl<IsEncryption>>(key);
    case AEAD::AES128GCM:
        return std::make_unique<AES128GCMImpl<IsEncryption>>(key);
    case AEAD::AES256GCM:
        return std::make_unique<AES256GCMImpl<IsEncryption>>(key);
    default:
        break;
    }

    return {};
}
} // namespace

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
