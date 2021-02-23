#include <cstring>
#include <iostream>

#include <asio/signal_set.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/io_context.hpp>

#include "Server.h"

void printUsage() {
    std::cerr << "usage: \n"
                 "    -p <server_port>           Port number of your remote server.\n"
                 "    -k <password>              Password of your remote server.\n";
}

static const char* port;
static const char* password;

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        using std::strcmp;

        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            printUsage();
            return 0;
        }

        if (!strcmp("-p", argv[i])) {
            port = argv[++i];
        } else if (!strcmp("-k", argv[i])) {
            password = argv[++i];
        }
    }

    if (!port || !password) {
        printUsage();
        return 0;
    }

    asio::io_context ctx;

    asio::signal_set signals(ctx, SIGINT, SIGTERM);
    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });

    asio::ip::tcp::endpoint endpoint{asio::ip::tcp::v4(),
                                     static_cast<unsigned short>(std::stoul(port))};
    Server server{ctx, endpoint, password};
    server.doAccept();

    ctx.run();
    return 0;
}
