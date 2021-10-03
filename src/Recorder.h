#ifndef RECORDER_H
#define RECORDER_H

#include <concepts>
#include <cstdint>

template <typename T>
concept Recorder = requires(T r, int64_t size) {
    { r.record(size) } -> std::same_as<void>;
};

struct DefaultRecorder {
    void record(int64_t);
};

#endif
