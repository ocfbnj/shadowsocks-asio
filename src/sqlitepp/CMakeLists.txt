add_library(sqlitepp STATIC sqlitepp.cpp SQLiteConnector.cpp SQLiteException.cpp)
target_include_directories(sqlitepp PRIVATE ${CMAKE_SOURCE_DIR}/include/sqlitepp)
target_link_libraries(sqlitepp PUBLIC SQLite::SQLite3 spdlog::spdlog)

add_library(ocfbnj::sqlitepp ALIAS sqlitepp)
