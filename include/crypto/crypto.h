#ifndef OCFBNJ_CYRPTO_CRYPTO_H
#define OCFBNJ_CYRPTO_CRYPTO_H

#include <cstdint>
#include <span>
#include <string>

namespace crypto {
// increment increment the number (little endian) by one.
void increment(std::span<std::uint8_t> num);

// toHexStream converts a bytes sequence to hex representation (lowercase).
std::string toHexStream(std::span<const std::uint8_t> str);

// toSpan converts a std::string to std::span
std::span<const std::uint8_t> toSpan(const std::string& str);

// toString converts a std::span to std::string
std::string toString(std::span<const std::uint8_t> str);

// deriveKey generate the master key from a password.
void deriveKey(std::span<const std::uint8_t> password, std::span<std::uint8_t> key);

// hkdfSha1 produces a subkey that is cryptographically strong even if the input secret key is weak.
void hkdfSha1(std::span<const std::uint8_t> key,
              std::span<const std::uint8_t> salt,
              std::span<const std::uint8_t> info,
              std::span<std::uint8_t> subkey);

// randomBytes generate random bytes.
void randomBytes(std::span<std::uint8_t> bytes);
} // namespace crypto

#endif
