#include <cstring>
#include <iostream>
#include <string_view>
#include <thread>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/io_context.hpp>
#include <spdlog/spdlog.h>

#include "tcp.h"
#include "type.h"

void printUsage() {
    std::cerr << "Usage: \n"
                 "    -p <server_port>           Port number of your remote server.\n"
                 "    -k <password>              Password of your remote server.\n\n"
                 "    -V                         Verbose mode.\n";
}

static std::string_view port;
static std::string_view password;
static bool remoteMode = true;

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        using std::strcmp;

        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            printUsage();
            return 0;
        }

        if (!strcmp("-V", argv[i])) {
            spdlog::set_level(spdlog::level::debug);
        }

        if (!strcmp("-p", argv[i])) {
            port = argv[++i];
        } else if (!strcmp("-k", argv[i])) {
            password = argv[++i];
        }
    }

    if (port.empty() || password.empty()) {
        printUsage();
        return 0;
    }

    asio::io_context ctx;

    asio::signal_set signals(ctx, SIGINT, SIGTERM);
    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });

    std::vector<std::thread> threadPool(std::thread::hardware_concurrency());
    for (std::thread& t : threadPool) {
        t = std::thread{[&ctx]() { ctx.run(); }};
    }

    if (remoteMode) {
        asio::co_spawn(ctx, tcpRemote(port, password), asio::detached);
    }

    ctx.run();

    for (std::thread& t : threadPool) {
        if (t.joinable()) {
            t.join();
        }
    }

    return 0;
}
