#include <cstdint>
#include <string_view>

#include <fmt/format.h>
#include <gtest/gtest.h>

#include "sqlitepp/sqlitepp.h"

constexpr std::string_view dbFilename = "test.db";

constexpr std::string_view createTableSql{R"(
create table if not exists record (
    request_host varchar(255) not null,
    target_host varchar(255) not null,
    bytes bigint default 0,
    times int default 1,

    primary key(request_host, target_host)
);)"};

constexpr std::string_view insertOrUpdateSql{R"(
insert or ignore
into
    record (request_host, target_host, bytes)
values
    ("{0}", "{1}", {2});

update
    record
set
    bytes = bytes + {2},
    times = times + 1
where
    request_host="{0}" and target_host="{1}";)"};

constexpr std::string_view requestHost = "127.0.0.1";
constexpr std::string_view targetHost = "google.com";
constexpr uint64_t bytes = 32768;

GTEST_TEST(connector, connect) {
    SQLiteConnector connector{dbFilename};
}

GTEST_TEST(connector, create_table) {
    SQLiteConnector connector{dbFilename};
    connector.exec(createTableSql);
}

GTEST_TEST(connector, insert_or_update_recoard) {
    SQLiteConnector connector{dbFilename};
    connector.exec(createTableSql);

    std::string sql = fmt::format(insertOrUpdateSql, requestHost, targetHost, bytes);
    connector.exec(sql);
}
