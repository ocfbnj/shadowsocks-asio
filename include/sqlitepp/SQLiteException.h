#ifndef SQLITE_EXCEPTION_H
#define SQLITE_EXCEPTION_H

#include <exception>
#include <string>
#include <string_view>

class SQLiteException : std::exception {
public:
    explicit SQLiteException(std::string_view errorMessage) noexcept;
    const char* what() const noexcept override;

private:
    std::string msg;
};

#endif
