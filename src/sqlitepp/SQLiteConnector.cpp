#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include "SQLiteConnector.h"
#include "SQLiteException.h"

SQLiteConnector::SQLiteConnector() noexcept : db(nullptr), errmsg(nullptr) {}

SQLiteConnector::SQLiteConnector(std::string_view filename) : SQLiteConnector() {
    open(filename);
}

SQLiteConnector::SQLiteConnector(SQLiteConnector&& other) noexcept {
    db = other.db;
    other.db = nullptr;
}

SQLiteConnector::~SQLiteConnector() {
    if (errmsg) {
        sqlite3_free(errmsg);
    }

    if (db) {
        auto ret = sqlite3_close(db);
        if (ret != SQLITE_OK) {
            spdlog::warn("close a sqlite3 connection error: {}", sqlite3_errstr(ret));
        } else {
            spdlog::trace("close a sqlite3 connection");
        }
    }
}

void SQLiteConnector::open(std::string_view filename) {
    auto ret = sqlite3_open(filename.data(), &db);
    if (ret != SQLITE_OK) {
        throw SQLiteException{sqlite3_errmsg(db)};
    }

    spdlog::trace("open a sqlite3 connection");
}

void SQLiteConnector::exec(std::string_view sql) {
    auto ret = sqlite3_exec(db, sql.data(), nullptr, nullptr, &errmsg);
    if (ret != SQLITE_OK) {
        throw SQLiteException{errmsg};
    }
}
