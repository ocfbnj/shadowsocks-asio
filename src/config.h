#ifndef CONFIG_H
#define CONFIG_H

#include <optional>
#include <string>

#include "ss_url.h"

struct config {
    std::string debug_str() const;
    bool verify_params();

    constexpr static std::string_view version = "v0.2.0";

    enum class running_mode {
        remote,
        local
    };

    running_mode mode;

    std::string method;
    std::string remote_host;
    std::string remote_port;
    std::string local_port;
    std::string password;

    std::optional<std::string> acl_file_path;
};

#endif
