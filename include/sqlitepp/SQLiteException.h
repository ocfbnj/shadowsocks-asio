#ifndef SQLITE_EXCEPTION
#define SQLITE_EXCEPTION

#include <exception>
#include <string>
#include <string_view>

class SQLiteException : std::exception {
public:
    SQLiteException(std::string_view errorMessage);
    const char* what() const noexcept override;

private:
    std::string msg;
};

#endif
