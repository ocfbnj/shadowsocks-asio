#include "SqliteTrafficRecorder.h"
#include "SqliteTrafficRecorderHelper.h"

void SqliteTrafficRecorder::record(int64_t size) {
    SqliteTrafficRecorderHelper::post(requestHost, targetHost, size);
}
