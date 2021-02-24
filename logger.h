// A very simple logger.

#ifndef LOGGER_H
#define LOGGER_H

#include <array>
#include <ctime>
#include <iostream>

enum LogType {
    MSG,
    WARN
};

inline std::ostream& log(LogType type = MSG) {
    std::array<char, 26> buf;
    std::time_t now = std::time(NULL);
    std::tm* s_tm = std::localtime(&now);

    std::strftime(buf.data(), buf.size(), "%F %T %z", s_tm);

    const char* t = nullptr;

    switch (type) {
    case MSG:
        t = "MSG";
        break;
    case WARN:
        t = "WARN";
        break;
    default:
        break;
    }

    return std::cerr << buf.data() << " [" << t << "] ";
}

#endif
