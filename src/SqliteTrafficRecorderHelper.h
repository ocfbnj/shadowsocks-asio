#ifndef TRAFFIC_RECORDER_HELPER_H
#define TRAFFIC_RECORDER_HELPER_H

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include "sqlitepp/sqlitepp.h"

using Hosts = std::pair<std::string, std::string>;

namespace std {
template <>
struct hash<Hosts> {
    std::size_t operator()(const Hosts& s) const noexcept {
        return std::hash<std::string>{}(s.first + s.second);
    }
};
} // namespace std

class SqliteTrafficRecorderHelper {
public:
    static void post(const std::string requestHost, const std::string targetHost, int64_t bytes);
    static std::string dbFilename;

private:
    SqliteTrafficRecorderHelper();
    SqliteTrafficRecorderHelper(const SqliteTrafficRecorderHelper&) = delete;
    SqliteTrafficRecorderHelper(SqliteTrafficRecorderHelper&&) = delete;
    ~SqliteTrafficRecorderHelper();

    void createTableIfNotExists();
    void insertOrUpdate(const Hosts& hosts, int64_t bytes);

    void loop();
    void dump(const std::unordered_map<Hosts, int64_t>& records);

    SQLiteConnector connector;
    std::unordered_map<Hosts, int64_t> records;

    bool stop;
    std::thread thrd;
    std::mutex mtx;
    std::condition_variable cond;
};

#endif
