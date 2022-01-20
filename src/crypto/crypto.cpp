#include <cassert>
#include <iomanip>
#include <sstream>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#include <crypto/crypto.h>

namespace crypto {
void increment(std::span<std::uint8_t> num) {
    std::size_t len = num.size();

    for (std::size_t i = 0; i != len; i++) {
        num[i]++;
        if (num[i] != 0) {
            break;
        }
    }
}

std::string toHexStream(std::span<const std::uint8_t> str) {
    std::ostringstream oss;
    for (const std::uint8_t byte : str) {
        oss << std::hex << std::setw(2) << std::setfill('0') << +byte;
    }

    return oss.str();
}

std::span<const std::uint8_t> toSpan(const std::string& str) {
    return std::span{reinterpret_cast<const std::uint8_t*>(str.data()), str.size()};
}

std::string toString(std::span<const std::uint8_t> str) {
    return std::string{reinterpret_cast<const char*>(str.data()), str.size()};
}

void deriveKey(std::span<const std::uint8_t> password, std::span<std::uint8_t> key) {
    std::size_t keySize = key.size();

    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    assert(md != nullptr);

    mbedtls_md_context_t ctx;
    int ret = mbedtls_md_setup(&ctx, md, 0);
    assert(ret == 0);

    std::array<std::uint8_t, MBEDTLS_MD_MAX_SIZE> mdBuf;
    std::uint8_t mds = mbedtls_md_get_size(md);

    for (int j = 0, addmd = 0; j < keySize; addmd++) {
        mbedtls_md_starts(&ctx);
        if (addmd) {
            mbedtls_md_update(&ctx, mdBuf.data(), mds);
        }
        mbedtls_md_update(&ctx, password.data(), password.size());
        mbedtls_md_finish(&ctx, mdBuf.data());

        for (int i = 0; i < mds; i++, j++) {
            if (j >= keySize) {
                break;
            }
            key[j] = mdBuf[i];
        }
    }

    mbedtls_md_free(&ctx);
}

void hkdfSha1(std::span<const std::uint8_t> key,
              std::span<const std::uint8_t> salt,
              std::span<const std::uint8_t> info,
              std::span<std::uint8_t> subkey) {
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_hkdf(mdInfo,
                 salt.data(), salt.size(),
                 key.data(), key.size(),
                 info.data(), info.size(),
                 subkey.data(), subkey.size());
}

void randomBytes(std::span<std::uint8_t> bytes) {
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_ctr_drbg_init(&ctrDrbg);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    int ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, nullptr, 0);
    assert(ret == 0);

    ret = mbedtls_ctr_drbg_random(&ctrDrbg, bytes.data(), bytes.size());
    assert(ret == 0);

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctrDrbg);
}
} // namespace crypto
