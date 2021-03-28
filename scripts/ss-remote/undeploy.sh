#!/bin/bash

name="shadowsocks-asio"
version="v0.0.4"

bin_file="/usr/local/bin/${name}"
ss_remote_start_file="/etc/${name}/ss-remote.sh"
ss_remote_service_name="ss-remote.service"
ss_remote_service_file="/etc/systemd/system/${ss_remote_service_name}"

# 1. Stop service.
systemctl disable --now ${ss_remote_service_name}

# 2. Remove all files except log files.
rm ${bin_file} ${ss_remote_start_file} ${ss_remote_service_file}

# 3. Reload the configuration file.
systemctl daemon-reload
