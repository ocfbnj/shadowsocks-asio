#include "SQLiteException.h"

SQLiteException::SQLiteException(std::string_view errorMessage) noexcept : msg(errorMessage) {}

const char* SQLiteException::what() const noexcept {
    return msg.data();
}
