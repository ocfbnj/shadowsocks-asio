#include "SQLiteTrafficRecorder.h"
#include "SQLiteTrafficRecorderHelper.h"

SQLiteTrafficRecorder::SQLiteTrafficRecorder(SQLiteTrafficRecorder&& other) noexcept {
    requestHost = std::move(other.requestHost);
    targetHost = std::move(other.targetHost);
    bytes = other.bytes;
    other.bytes = 0;
}

SQLiteTrafficRecorder::~SQLiteTrafficRecorder() noexcept {
    if (bytes > 0) {
        SQLiteTrafficRecorderHelper::post(requestHost, targetHost, bytes);
    }
}

void SQLiteTrafficRecorder::record(int64_t size) noexcept {
    bytes += size;

    constexpr int64_t MB = 1024 * 1024;
    if (bytes >= MB) {
        SQLiteTrafficRecorderHelper::post(requestHost, targetHost, bytes);
        bytes = 0;
    }
}
