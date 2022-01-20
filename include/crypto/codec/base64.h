#ifndef OCFBNJ_CRYPTO_BASE64_H
#define OCFBNJ_CRYPTO_BASE64_H

#include <cstdint>
#include <span>
#include <vector>

namespace crypto {
namespace codec {
namespace base64 {
// encode encode src to base64 format.
std::vector<std::uint8_t> encode(std::span<const std::uint8_t> src);

// decode decode base64 encoded src to original format.
// throw `DecodingError` if the base64 characters are invalid.
std::vector<std::uint8_t> decode(std::span<const std::uint8_t> src);
} // namespace base64
} // namespace codec
} // namespace crypto

#endif
