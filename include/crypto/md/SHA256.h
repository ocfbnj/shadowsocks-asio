#ifndef OCFBNJ_CRYPTO_SHA256_H
#define OCFBNJ_CRYPTO_SHA256_H

#include <cstdint>
#include <span>
#include <vector>

namespace crypto {
namespace md {
class SHA256 {
public:
    static constexpr std::size_t Size = 32;

    static std::vector<std::uint8_t> get(std::span<const std::uint8_t> msg);

    SHA256();
    ~SHA256();

    void starts();
    void update(std::span<const std::uint8_t> msg);
    std::vector<std::uint8_t> finish();

private:
    void* ptr;
};
} // namespace md
} // namespace crypto

#endif
