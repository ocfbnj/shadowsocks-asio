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

#include "AEAD.h"
#include "tcp.h"
#include "type.h"

static bool remoteMode = true;

static std::string_view remoteHost;
static std::string_view remotePort;
static std::string_view localPort;
static std::string_view password;

static AEAD::Cipher cipherType = AEAD::ChaCha20Poly1305;

void printUsage() {
    std::cout << "Usage: \n"
                 "    --Server                   Server mode. (Default)\n"
                 "    --Client                   Client mode.\n"
                 "\n"
                 "    -s <server host>           Host name or IP address of your remote server.\n"
                 "    -p <server port>           Port number of your remote server.\n"
                 "    -l <local port>            Port number of your local server.\n"
                 "    -k <password>              Password of your remote server.\n"
                 "\n"
                 "    -V                         Verbose mode.\n";
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        using std::strcmp;

        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            printUsage();
            return 0;
        } else if (!strcmp("--Client", argv[i])) {
            remoteMode = false;
        } else if (!strcmp("-V", argv[i])) {
            spdlog::set_level(spdlog::level::debug);
        } else if (!strcmp("-s", argv[i])) {
            remoteHost = argv[++i];
        } else if (!strcmp("-p", argv[i])) {
            remotePort = argv[++i];
        } else if (!strcmp("-l", argv[i])) {
            localPort = argv[++i];
        } else if (!strcmp("-k", argv[i])) {
            password = argv[++i];
        }
    }

    asio::io_context ctx;

    if (remoteMode) {
        if (remotePort.empty() || password.empty()) {
            printUsage();
            return 0;
        }

        asio::co_spawn(ctx, tcpRemote(cipherType, remotePort, password), asio::detached);
    } else {
        if (remoteHost.empty() || remotePort.empty() || localPort.empty() || password.empty()) {
            printUsage();
            return 0;
        }

        asio::co_spawn(ctx, tcpLocal(cipherType, remoteHost, remotePort, localPort, password), asio::detached);
    }

    asio::signal_set signals(ctx, SIGINT, SIGTERM);
    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });

    std::vector<std::jthread> threadPool(std::thread::hardware_concurrency());
    for (std::jthread& t : threadPool) {
        t = std::jthread{[&ctx]() { ctx.run(); }};
    }

    ctx.run();

    return 0;
}
