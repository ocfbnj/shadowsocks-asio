#ifndef SQLITE_TRAFFIC_RECORDER
#define SQLITE_TRAFFIC_RECORDER

#include "TrafficRecorder.h"

struct SqliteTrafficRecorder {
    void record(int64_t size);

    std::string requestHost;
    std::string targetHost;
};

#endif
