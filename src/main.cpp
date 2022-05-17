#include <cstring>
#include <iostream>
#include <optional>
#include <thread>
#include <vector>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#include <asio/ts/io_context.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include "config.h"
#include "convert.h"
#include "ss_url.h"
#include "tcp.h"

namespace {
config conf = {.mode = config::running_mode::remote};

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
                             config::version);
}
} // namespace

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        using std::strcmp;

        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            print_usage();
            return 0;
        } else if (!strcmp("--version", argv[i]) || !strcmp("-v", argv[i])) {
            std::cout << config::version << "\n";
            return 0;
        } else if (!strcmp("--Client", argv[i])) {
            conf.mode = config::running_mode::local;
        } else if (!strcmp("-s", argv[i])) {
            conf.remote_host = argv[++i];
        } else if (!strcmp("-p", argv[i])) {
            conf.remote_port = argv[++i];
        } else if (!strcmp("-l", argv[i])) {
            conf.local_port = argv[++i];
        } else if (!strcmp("-k", argv[i])) {
            conf.password = argv[++i];
        } else if (!strcmp("-m", argv[i])) {
            conf.method = argv[++i];
        } else if (!strcmp("--acl", argv[i])) {
            conf.acl_file_path = argv[++i];
        } else if (!strcmp("--url", argv[i])) {
            ss_url url = ss_url::parse(argv[++i]);

            conf.method = url.userinfo.method;
            conf.password = url.userinfo.password;
            conf.remote_host = url.hostname;
            conf.remote_port = url.port;
        } else if (!strcmp("-V", argv[i])) {
            spdlog::set_level(spdlog::level::debug);
        } else if (!strcmp("-VV", argv[i])) {
            spdlog::set_level(spdlog::level::trace);
        }
    }

    if (conf.method.empty()) {
        conf.method = "chacha20-ietf-poly1305";
    }

    auto encrypt_method = method_from_string(conf.method);
    if (!encrypt_method) {
        std::cout << "Invalid encrypt method: " + conf.method << "\n";
        return -1;
    }

    if (!conf.verify_params()) {
        print_usage();
        return -1;
    }

    spdlog::debug("{}", conf.debug_str());

    asio::io_context ctx;

    switch (conf.mode) {
    case config::running_mode::remote:
        asio::co_spawn(ctx, tcp_remote(std::move(conf)), asio::detached);
        break;
    case config::running_mode::local:
        asio::co_spawn(ctx, tcp_local(std::move(conf)), asio::detached);
        break;
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
