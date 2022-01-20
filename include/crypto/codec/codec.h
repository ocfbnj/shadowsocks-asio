#ifndef OCFBNJ_CRYPTO_CODEC_H
#define OCFBNJ_CRYPTO_CODEC_H

#include <stdexcept>

namespace crypto {
namespace codec {
class DecodingError : public std::runtime_error {
public:
    using runtime_error::runtime_error;
};
} // namespace codec
} // namespace crypto

#endif
