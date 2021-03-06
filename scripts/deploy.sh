#!/bin/bash

name="shadowsocks-asio"
version="v0.0.2"

download_file="${name}.tar.gz"
url="https://github.com/ocfbnj/${name}/releases/download/${version}/${download_file}"

start_file="/etc/${name}/start.sh"
log_file="/var/log/${name}/ss.log"
service_file="/etc/systemd/system/${name}.service"

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
cat <<EOF > ${start_file}
#!/bin/sh
${name} -p ${default_port} -k ${default_password} 2>> ${log_file} &
EOF

chmod ug+x ${start_file}

# 4. Create service.
cat <<EOF > ${service_file}
[Unit]
Description=${name} remote server
After=network.target

[Service]
Type=forking
ExecStart=${start_file}

[Install]
WantedBy=default.target
EOF

# 5. Start service.
systemctl daemon-reload
systemctl enable --now ${name}.service

# 6. Clean up
rm /root/${download_file}

echo "== Done =="
