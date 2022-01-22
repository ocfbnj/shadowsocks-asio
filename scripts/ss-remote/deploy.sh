#!/bin/bash

name="shadowsocks-asio"
version="v0.1.0"

download_file="${name}.tar.gz"
url="https://github.com/ocfbnj/${name}/releases/download/${version}/${download_file}"

ss_remote_start_file="/etc/${name}/ss-remote.sh"
ss_remote_log_file="/var/log/${name}/ss-remote.log"
ss_remote_service_name="ss-remote.service"
ss_remote_service_file="/etc/systemd/system/${ss_remote_service_name}"

default_port="5421"
default_password="ocfbnj"

echo "== ${name} ${version} =="

# 1. Download and unzip the program.
cd /root/
wget ${url}
tar -C /usr/local/bin -xzf ${download_file}

# 2. Create directories.
mkdir -p "/etc/${name}"
mkdir -p "/var/log/${name}"

# 3. Create startup script.
cat <<EOF > ${ss_remote_start_file}
#!/bin/sh
${name} -p ${default_port} -k ${default_password} >> ${ss_remote_log_file} &
EOF

chmod ug+x ${ss_remote_start_file}

# 4. Create service.
cat <<EOF > ${ss_remote_service_file}
[Unit]
Description=${name} remote server
After=network.target

[Service]
Type=forking
ExecStart=${ss_remote_start_file}

[Install]
WantedBy=default.target
EOF

# 5. Start service.
systemctl daemon-reload
systemctl enable --now ${ss_remote_service_name}

# 6. Clean up.
rm /root/${download_file}

echo "== Done =="
