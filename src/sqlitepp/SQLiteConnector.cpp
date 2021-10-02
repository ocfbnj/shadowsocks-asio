#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include "SQLiteConnector.h"
#include "SQLiteException.h"

SQLiteConnector::SQLiteConnector() : db(nullptr), errmsg(nullptr) {}

SQLiteConnector::SQLiteConnector(std::string_view filename) : SQLiteConnector() {
    open(filename);
}

SQLiteConnector::SQLiteConnector(SQLiteConnector&& other) {
    db = other.db;
    other.db = nullptr;
}

SQLiteConnector::~SQLiteConnector() {
    if (errmsg) {
        sqlite3_free(errmsg);
    }

    if (db) {
        sqlite3_close(db);
    }

    spdlog::debug("close a sqlite3 connection");
}

void SQLiteConnector::open(std::string_view filename) {
    // auto ret = sqlite3_open_v2(filename.data(),
    //                            &db,
    //                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
    //                            nullptr);

    auto ret = sqlite3_open(filename.data(), &db);
    if (ret != SQLITE_OK) {
        throw SQLiteException{sqlite3_errmsg(db)};
    }

    spdlog::debug("open a sqlite3 connection");
}

void SQLiteConnector::exec(std::string_view sql) {
    auto ret = sqlite3_exec(db, sql.data(), nullptr, nullptr, &errmsg);
    if (ret != SQLITE_OK) {
        throw SQLiteException{errmsg};
    }
}
