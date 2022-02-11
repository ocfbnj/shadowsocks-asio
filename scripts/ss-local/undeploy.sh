#!/bin/bash

name="shadowsocks-asio"
version="v0.1.1"

bin_file="/usr/local/bin/${name}"
ss_local_start_file="/etc/${name}/ss-local.sh"
ss_local_service_name="ss-local.service"
ss_local_service_file="/etc/systemd/system/${ss_local_service_name}"

# 1. Stop service.
systemctl disable --now ${ss_local_service_name}

# 2. Remove all files except log files.
rm ${bin_file} ${ss_local_start_file} ${ss_local_service_file}

# 3. Reload the configuration file.
systemctl daemon-reload
