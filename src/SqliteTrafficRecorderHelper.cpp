#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include "SqliteTrafficRecorderHelper.h"

std::string SqliteTrafficRecorderHelper::dbFilename;

SqliteTrafficRecorderHelper::SqliteTrafficRecorderHelper()
    : connector(dbFilename),
      stop(false),
      thrd(&SqliteTrafficRecorderHelper::loop, this) {
    createTableIfNotExists();

    spdlog::debug("create traffic recorder helper");
}

SqliteTrafficRecorderHelper::~SqliteTrafficRecorderHelper() {
    {
        std::unique_lock<std::mutex> lock{mtx};
        stop = true;
    }

    cond.notify_all();

    if (thrd.joinable()) {
        thrd.join();
    }

    spdlog::debug("destory traffic recorder helper");
}

void SqliteTrafficRecorderHelper::createTableIfNotExists() {
    constexpr std::string_view createTableSql{R"(
create table if not exists record (
    request_host varchar(255) not null,
    target_host varchar(255) not null,
    bytes bigint default 0,
    times int default 1,

    primary key(request_host, target_host)
);)"};

    connector.exec(createTableSql);
}

void SqliteTrafficRecorderHelper::insertOrUpdate(const Hosts& hosts, int64_t bytes) {
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

    std::string sql = fmt::format(insertOrUpdateSql, hosts.first, hosts.second, bytes);
    connector.exec(sql);
}

void SqliteTrafficRecorderHelper::post(const std::string requestHost, const std::string targetHost, int64_t bytes) {
    static SqliteTrafficRecorderHelper helper;

    {
        std::lock_guard<std::mutex> guard{helper.mtx};
        helper.records[{requestHost, targetHost}] += bytes;
    }

    helper.cond.notify_all();
}

void SqliteTrafficRecorderHelper::loop() {
    while (true) {
        std::unordered_map<Hosts, int64_t> rs;

        {
            std::unique_lock<std::mutex> lock{mtx};
            cond.wait(lock, [this] { return !records.empty() || stop; });

            if (stop) {
                return;
            }

            records.swap(rs);
        }

        dump(rs);

        using namespace std::literals;
        std::this_thread::sleep_for(1s);
    }
}

void SqliteTrafficRecorderHelper::dump(const std::unordered_map<Hosts, int64_t>& records) {
    for (auto&& [hosts, bytes] : records) {
        insertOrUpdate(hosts, bytes);
    }
}
