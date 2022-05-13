#include <algorithm>
#include <cassert>

#include <crypto/crypto.h>

#include "replay_protection.h"

replay_protection& replay_protection::get() {
    static replay_protection instance;
    return instance;
}

replay_protection::replay_protection() {
    bloom_parameters parameters;
    parameters.projected_element_count = count;
    parameters.false_positive_probability = 1e-6;
    unsigned long long seed;
    crypto::randomBytes(std::span{reinterpret_cast<std::uint8_t*>(&seed), sizeof(seed)});
    parameters.random_seed = seed;

    bool ok = parameters.compute_optimal_parameters();
    assert(ok);

    for (auto& filter : filters) {
        filter = bloom_filter{parameters};
    }
}

void replay_protection::insert(std::span<const std::uint8_t> element) {
    bloom_filter& bloom_filter = filters[current];

    std::lock_guard lock{mtx};
    bloom_filter.insert(element.data(), element.size());

    if (bloom_filter.element_count() >= count) {
        current = !current;
        filters[current].clear();
    }
}

bool replay_protection::contains(std::span<const std::uint8_t> element) {
    std::lock_guard lock{mtx};
    return std::any_of(filters.begin(), filters.end(), [element](auto& filter) {
        return filter.contains(element.data(), element.size());
    });
}
