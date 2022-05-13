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

#include "ss_url.h"
#include "tcp.h"

namespace {
constexpr std::string_view version = "v0.1.1";

bool remote_mode = true;

std::string remote_host;
std::string remote_port;
std::string local_port;
std::string password;
std::string acl_file_path;
std::string method = "chacha20-ietf-poly1305";

void print_usage() {
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
                             version);
}

void print_debug_info() {
    ss_url ssurl{
        .userinfo = {
            .method = method,
            .password = password,
        },
        .hostname = remote_host,
        .port = remote_port,
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

crypto::AEAD::Method pick_cipher(std::string_view method) {
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
            print_usage();
            return 0;
        } else if (!strcmp("--version", argv[i]) || !strcmp("-v", argv[i])) {
            std::cout << version << "\n";
            return 0;
        } else if (!strcmp("--Client", argv[i])) {
            remote_mode = false;
        } else if (!strcmp("-s", argv[i])) {
            remote_host = argv[++i];
        } else if (!strcmp("-p", argv[i])) {
            remote_port = argv[++i];
        } else if (!strcmp("-l", argv[i])) {
            local_port = argv[++i];
        } else if (!strcmp("-k", argv[i])) {
            password = argv[++i];
        } else if (!strcmp("-m", argv[i])) {
            method = argv[++i];
        } else if (!strcmp("--acl", argv[i])) {
            acl_file_path = argv[++i];
        } else if (!strcmp("--url", argv[i])) {
            ss_url url = ss_url::parse(argv[++i]);

            method = url.userinfo.method;
            password = url.userinfo.password;
            remote_host = url.hostname;
            remote_port = url.port;
        } else if (!strcmp("-V", argv[i])) {
            spdlog::set_level(spdlog::level::debug);
        }
    }

    crypto::AEAD::Method encrypt_method = pick_cipher(method);
    if (encrypt_method == crypto::AEAD::Invalid) {
        std::cout << "Invalid encrypt method: " + method << "\n";
        return 0;
    }

    if (remote_mode) {
        if (remote_host.empty()) {
            remote_host = "0.0.0.0";
        }

        if (remote_port.empty() || password.empty()) {
            print_usage();
            return 0;
        }
    } else {
        if (remote_host.empty() || remote_port.empty() || local_port.empty() || password.empty()) {
            print_usage();
            return 0;
        }
    }

    print_debug_info();

    asio::io_context ctx;

    std::optional<std::string> acl;
    if (!acl_file_path.empty()) {
        acl = acl_file_path;
    }

    if (remote_mode) {
        asio::co_spawn(ctx, tcp_remote(encrypt_method, remote_host, remote_port, password, acl), asio::detached);
    } else {
        asio::co_spawn(ctx, tcp_local(encrypt_method, remote_host, remote_port, local_port, password, acl), asio::detached);
    }

    asio::signal_set signals(ctx, SIGINT, SIGTERM);
    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });

    std::vector<std::thread> thread_pool(std::thread::hardware_concurrency());
    for (std::thread& t : thread_pool) {
        t = std::thread{[&ctx]() { ctx.run(); }};
    }

    ctx.run();

    for (std::thread& t : thread_pool) {
        if (t.joinable()) {
            t.join();
        }
    }

    return 0;
}
