#include "SQLiteException.h"

SQLiteException::SQLiteException(std::string_view errorMessage) : msg(errorMessage) {}

const char* SQLiteException::what() const noexcept {
    return msg.data();
}
