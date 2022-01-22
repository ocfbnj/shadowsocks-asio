#include <algorithm>
#include <cassert>

#include "ReplayProtection.h"

ReplayProtection& ReplayProtection::get() {
    static ReplayProtection replayProtection;
    return replayProtection;
}

ReplayProtection::ReplayProtection() {
    bloom_parameters parameters;
    parameters.projected_element_count = count;
    parameters.false_positive_probability = 1e-6;

    bool ok = parameters.compute_optimal_parameters();
    assert(ok);

    for (auto& filter : filters) {
        filter = bloom_filter{parameters};
    }
}

void ReplayProtection::insert(std::span<const std::uint8_t> element) {
    bloom_filter& bloomFilter = filters[current];

    std::lock_guard lock{mtx};
    bloomFilter.insert(element.data(), element.size());

    if (bloomFilter.element_count() >= count) {
        current = !current;
        filters[current].clear();
    }
}

bool ReplayProtection::contains(std::span<const std::uint8_t> element) {
    std::lock_guard lock{mtx};
    return std::any_of(filters.begin(), filters.end(), [element](auto& filter) {
        return filter.contains(element.data(), element.size());
    });
}
