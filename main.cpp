#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/io_context.hpp>

#include "Server.h"

void printUsage() {
    std::cerr << "Usage: \n"
                 "    -p <server_port>           Port number of your remote server.\n"
                 "    -k <password>              Password of your remote server.\n";
}

static std::uint16_t port;
static std::string_view password;

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        using std::strcmp;

        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            printUsage();
            return 0;
        }

        if (!strcmp("-p", argv[i])) {
            port = static_cast<std::uint16_t>(std::stoul(argv[++i]));
        } else if (!strcmp("-k", argv[i])) {
            password = argv[++i];
        }
    }

    if (port == 0 || std::empty(password)) {
        printUsage();
        return 0;
    }

    asio::io_context ctx;

    asio::signal_set signals(ctx, SIGINT, SIGTERM);
    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });

    Server server{password};
    asio::co_spawn(ctx, server.listen({asio::ip::tcp::v4(), port}), asio::detached);

    ctx.run();
    return 0;
}
