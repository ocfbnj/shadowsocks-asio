#include <sqlite3.h>

#include "sqlitepp.h"

void setSingleThread() {
    auto ret = sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
    if (ret != SQLITE_OK) {
        throw SQLiteException{sqlite3_errstr(ret)};
    }
}
