#ifndef SQLITE_TRAFFIC_RECORDER_H
#define SQLITE_TRAFFIC_RECORDER_H

#include "TrafficRecorder.h"

struct SQLiteTrafficRecorder {
    SQLiteTrafficRecorder() = default;
    SQLiteTrafficRecorder(const SQLiteTrafficRecorder&) = delete;
    SQLiteTrafficRecorder(SQLiteTrafficRecorder&&) noexcept;
    ~SQLiteTrafficRecorder() noexcept;

    void record(int64_t size) noexcept;

    std::string requestHost;
    std::string targetHost;
    int64_t bytes;
};

#endif
