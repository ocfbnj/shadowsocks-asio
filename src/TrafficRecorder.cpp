#include <iostream>

#include <fmt/format.h>

#include "TrafficRecorder.h"

void PrinterTrafficRecorder::record(int64_t size) {
    std::cout << fmt::format("{} -> {} bytes: {}\n", requestHost, targetHost, size);
}
