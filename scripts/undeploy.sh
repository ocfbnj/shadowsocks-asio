#!/bin/bash

name="shadowsocks-asio"
version="v0.0.3"

start_file="/etc/${name}/start.sh"
bin_file="/usr/local/bin/${name}"
service_file="/etc/systemd/system/${name}.service"

# 1. Stop service.
systemctl disable --now ${name}.service

# 2. Remove all files except log files.
rm ${start_file} ${log_file} ${bin_file} ${service_file}

# 3. reload the configuration file.
systemctl daemon-reload
