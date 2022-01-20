#include <mbedtls/base64.h>

#include <crypto/codec/base64.h>
#include <crypto/codec/codec.h>

namespace crypto {
namespace codec {
namespace base64 {
// encode encode src to base64 format.
std::vector<std::uint8_t> encode(std::span<const std::uint8_t> src) {
    std::vector<std::uint8_t> res(src.size() * 2);
    std::size_t olen;

    int ret = mbedtls_base64_encode(res.data(), res.size(), &olen, src.data(), src.size());
    assert(ret == 0);

    res.resize(olen);

    return res;
}

// decode decode base64 encoded src to original format.
// throw `DecodingError` if the base64 characters are invalid.
std::vector<std::uint8_t> decode(std::span<const std::uint8_t> src) {
    std::vector<std::uint8_t> res(src.size());
    std::size_t olen = 0;

    int ret = mbedtls_base64_decode(res.data(), res.size(), &olen, src.data(), src.size());

    if (ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        throw crypto::codec::DecodingError{"base64 invalid character"};
    }

    assert(ret == 0);

    res.resize(olen);

    return res;
}
} // namespace base64
} // namespace codec
} // namespace crypto
