#!/bin/bash

name="shadowsocks-asio"
version="v0.0.2-alpha"

download_file="${name}.tar.gz"
url="https://github.com/ocfbnj/${name}/releases/download/${version}/${download_file}"

start_file="/root/start.sh"
log_file="/root/ss.log"

default_port="5421"
default_password="ocfbnj"

echo "== ${name} ${version} =="

# 1. Download and unzip the program.
cd /root/
wget ${url}
tar -C /usr/local/bin -xzf ${download_file}

# 2. Create startup script.
cat <<EOF > ${start_file}
#!/bin/sh
${name} -p ${default_port} -k ${default_password} 2>> ${log_file} &
EOF

chmod ug+x ${start_file}

# 3. Create service.
cat <<EOF > /etc/systemd/system/${name}.service
[Unit]
Description=${name} remote server
After=network.target

[Service]
Type=forking
ExecStart=${start_file}

[Install]
WantedBy=mutil-user.target
EOF

# 4. Start service.
systemctl daemon-reload
systemctl enable --now ${name}.service

echo "== Done =="
