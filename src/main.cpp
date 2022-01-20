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

#include <crypto/aead/AEAD.h>

#include "tcp.h"

static bool remoteMode = true;

static std::string_view remoteHost;
static std::string_view remotePort;
static std::string_view localPort;
static std::string_view password;

static crypto::AEAD::Method method = crypto::AEAD::ChaCha20Poly1305;

static void printUsage() {
    std::cout << "Usage: \n"
                 "    --Server                   Server mode. (Default)\n"
                 "    --Client                   Client mode.\n"
                 "\n"
                 "    -s <server host>           Host name or IP address of your remote server.\n"
                 "    -p <server port>           Port number of your remote server.\n"
                 "    -l <local port>            Port number of your local server.\n"
                 "    -k <password>              Password of your remote server.\n"
                 "\n"
                 "    -m <encrypt method>        Encrypt method:\n"
                 "                               aes-128-gcm, aes-256-gcm,\n"
                 "                               chacha20-ietf-poly1305 (Default).\n"
                 "\n"
                 "    -V                         Verbose mode.\n";
}

static crypto::AEAD::Method pickCipher(std::string_view method) {
    crypto::AEAD::Method res = crypto::AEAD::Invalid;

    if (method == "chacha20-ietf-poly1305") {
        res = crypto::AEAD::ChaCha20Poly1305;
    } else if (method == "aes-128-gcm") {
        res = crypto::AEAD::AES128GCM;
    } else if (method == "aes-256-gcm") {
        res = crypto::AEAD::AES256GCM;
    }

    return res;
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        using std::strcmp;

        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            printUsage();
            return 0;
        } else if (!strcmp("--Client", argv[i])) {
            remoteMode = false;
        } else if (!strcmp("-s", argv[i])) {
            remoteHost = argv[++i];
        } else if (!strcmp("-p", argv[i])) {
            remotePort = argv[++i];
        } else if (!strcmp("-l", argv[i])) {
            localPort = argv[++i];
        } else if (!strcmp("-k", argv[i])) {
            password = argv[++i];
        } else if (!strcmp("-m", argv[i])) {
            method = pickCipher(argv[++i]);
        } else if (!strcmp("-V", argv[i])) {
            spdlog::set_level(spdlog::level::debug);
        }
    }

    if (method == crypto::AEAD::Invalid) {
        std::cout << "Invalid encrypt method.\n\n";
        printUsage();
        return 0;
    }

    asio::io_context ctx;

    if (remoteMode) {
        if (remotePort.empty() || password.empty()) {
            printUsage();
            return 0;
        }

        asio::co_spawn(ctx, tcpRemote(method, remotePort, password), asio::detached);
    } else {
        if (remoteHost.empty() || remotePort.empty() || localPort.empty() || password.empty()) {
            printUsage();
            return 0;
        }

        asio::co_spawn(ctx, tcpLocal(method, remoteHost, remotePort, localPort, password), asio::detached);
    }

    asio::signal_set signals(ctx, SIGINT, SIGTERM);
    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });

    std::vector<std::thread> threadPool(std::thread::hardware_concurrency());
    for (std::thread& t : threadPool) {
        t = std::thread{[&ctx]() { ctx.run(); }};
    }

    ctx.run();

    for (std::thread& t : threadPool) {
        if (t.joinable()) {
            t.join();
        }
    }

    return 0;
}
