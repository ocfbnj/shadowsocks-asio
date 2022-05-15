#include <fmt/format.h>

#include "config.h"

std::string config::debug_str() const {
    ss_url ssurl = {
        .userinfo = {
            .method = method,
            .password = password,
        },
        .hostname = remote_host,
        .port = remote_port,
    };

    return fmt::format("\n=======================================\n"
                       "hostname: {}\n"
                       "port: {}\n"
                       "method: {}\n"
                       "password: {}\n"
                       "SS-URL: {}\n"
                       "=======================================",
                       ssurl.hostname,
                       ssurl.port,
                       ssurl.userinfo.method,
                       ssurl.userinfo.password,
                       ssurl.encode());
}

bool config::verify_params() {
    switch (mode) {
    case running_mode::remote:
        if (remote_host.empty()) {
            remote_host = "0.0.0.0";
        }

        if (remote_port.empty() || password.empty()) {
            return false;
        }

        break;
    case running_mode::local:
        if (remote_host.empty() || remote_port.empty() || local_port.empty() || password.empty()) {
            return false;
        }

        break;
    }

    return true;
}
