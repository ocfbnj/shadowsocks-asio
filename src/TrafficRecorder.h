#ifndef TRAFFIC_RECORDER_H
#define TRAFFIC_RECORDER_H

#include <string>

#include "Recorder.h"

template <typename T>
concept TrafficRecorder = Recorder<T> && requires(T r, std::string host) {
    r.requestHost = host;
    r.targetHost = host;
};

// for test
struct PrinterTrafficRecorder {
    void record(int64_t size);

    std::string requestHost;
    std::string targetHost;
};

#endif
