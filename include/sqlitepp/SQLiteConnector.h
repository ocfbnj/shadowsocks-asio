#ifndef SQLITECONNECTOR_H
#define SQLITECONNECTOR_H

#include <string_view>

struct sqlite3;

class SQLiteConnector {
public:
    SQLiteConnector() noexcept;
    explicit SQLiteConnector(std::string_view filename);
    SQLiteConnector(const SQLiteConnector&) = delete;
    SQLiteConnector(SQLiteConnector&& other) noexcept;
    ~SQLiteConnector();

    void open(std::string_view filename);
    void exec(std::string_view sql);

private:
    sqlite3* db;
    char* errmsg;
};

#endif
