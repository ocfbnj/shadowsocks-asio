#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include "SQLiteTrafficRecorderHelper.h"

std::string SQLiteTrafficRecorderHelper::dbFilename;

void SQLiteTrafficRecorderHelper::post(const std::string requestHost, const std::string targetHost, int64_t bytes) {
    static SQLiteTrafficRecorderHelper helper;

    spdlog::trace("post {} => {}, {} bytes", requestHost, targetHost, bytes);

    {
        std::lock_guard<std::mutex> guard{helper.mtx};
        helper.records[{requestHost, targetHost}] += bytes;
    }

    helper.cond.notify_one();
}

SQLiteTrafficRecorderHelper::SQLiteTrafficRecorderHelper()
    : connector(dbFilename),
      stop(false),
      thrd(&SQLiteTrafficRecorderHelper::loop, this) {
    createTableIfNotExists();

    spdlog::trace("create sqlite traffic recorder helper");
}

SQLiteTrafficRecorderHelper::~SQLiteTrafficRecorderHelper() {
    {
        std::unique_lock<std::mutex> lock{mtx};
        stop = true;
    }

    cond.notify_all();

    if (thrd.joinable()) {
        thrd.join();
    }

    spdlog::trace("destory sqlite traffic recorder helper");
}

void SQLiteTrafficRecorderHelper::createTableIfNotExists() {
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

void SQLiteTrafficRecorderHelper::insertOrUpdate(const Hosts& hosts, int64_t bytes) {
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

void SQLiteTrafficRecorderHelper::loop() {
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

void SQLiteTrafficRecorderHelper::dump(const std::unordered_map<Hosts, int64_t>& records) {
    for (auto&& [hosts, bytes] : records) {
        insertOrUpdate(hosts, bytes);
    }
}
