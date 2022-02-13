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
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <crypto/aead/AEAD.h>

#include "SSURL.h"
#include "tcp.h"

namespace {
constexpr std::string_view Version = "v0.1.1";

bool remoteMode = true;

std::string remoteHost;
std::string remotePort;
std::string localPort;
std::string password;
std::string aclFilePath;
std::string method = "chacha20-ietf-poly1305";

void printUsage() {
    std::cout << fmt::format("shadowsocks-asio {}\n"
                             "A lightweight shadowsocks implementation using Asio and C++20 Coroutines.\n"
                             "\n"
                             "USAGE: ./shadowsocks-asio [FLAGS] [OPTIONS]\n"
                             "\n"
                             "FLAGS:\n"
                             "    --Server                   Server mode (Default)\n"
                             "    --Client                   Client mode\n"
                             "    -h, --help                 Print help information\n"
                             "    -v, --version              Print version information\n"
                             "    -V                         Verbose mode\n"
                             "\n"
                             "OPTIONS:\n"
                             "    -s <server host>           Host name or IP address of your remote server\n"
                             "    -p <server port>           Port number of your remote server\n"
                             "    -l <local port>            Port number of your local server\n"
                             "    -k <password>              Password of your remote server\n"
                             "\n"
                             "    -m <encrypt method>        Encrypt method:\n"
                             "                               aes-128-gcm, aes-256-gcm,\n"
                             "                               chacha20-ietf-poly1305 (Default)\n"
                             "\n"
                             "    --acl <file path>          Access control list\n"
                             "    --url <SS-URL>             SS-URL\n"
                             "\n",
                             Version);
}

void printDebugInfo() {
    SSURL ssurl{
        .userinfo = {
            .method = method,
            .password = password,
        },
        .hostname = remoteHost,
        .port = remotePort,
    };

    spdlog::debug("\n=======================================\n"
                  "| hostname: {}\n"
                  "| port: {}\n"
                  "| method: {}\n"
                  "| password: {}\n"
                  "| SS-URL: {}\n"
                  "=======================================",
                  ssurl.hostname, ssurl.port, ssurl.userinfo.method, ssurl.userinfo.password, ssurl.encode());
}

crypto::AEAD::Method pickCipher(std::string_view method) {
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
} // namespace

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        using std::strcmp;

        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            printUsage();
            return 0;
        } else if (!strcmp("--version", argv[i]) || !strcmp("-v", argv[i])) {
            std::cout << Version << "\n";
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
            method = argv[++i];
        } else if (!strcmp("--acl", argv[i])) {
            aclFilePath = argv[++i];
        } else if (!strcmp("--url", argv[i])) {
            SSURL url = SSURL::parse(argv[++i]);

            method = url.userinfo.method;
            password = url.userinfo.password;
            remoteHost = url.hostname;
            remotePort = url.port;
        } else if (!strcmp("-V", argv[i])) {
            spdlog::set_level(spdlog::level::debug);
        }
    }

    crypto::AEAD::Method encryptMethod = pickCipher(method);
    if (encryptMethod == crypto::AEAD::Invalid) {
        std::cout << "Invalid encrypt method: " + method << "\n";
        return 0;
    }

    if (remoteMode) {
        if (remoteHost.empty()) {
            remoteHost = "0.0.0.0";
        }

        if (remotePort.empty() || password.empty()) {
            printUsage();
            return 0;
        }
    } else {
        if (remoteHost.empty() || remotePort.empty() || localPort.empty() || password.empty()) {
            printUsage();
            return 0;
        }
    }

    printDebugInfo();

    asio::io_context ctx;

    std::optional<std::string> acl;
    if (!aclFilePath.empty()) {
        acl = aclFilePath;
    }

    if (remoteMode) {
        asio::co_spawn(ctx, tcpRemote(encryptMethod, remoteHost, remotePort, password, acl), asio::detached);
    } else {
        asio::co_spawn(ctx, tcpLocal(encryptMethod, remoteHost, remotePort, localPort, password, acl), asio::detached);
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
