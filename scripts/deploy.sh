#!/bin/bash

name="shadowsocks-asio"
version="v0.0.1"

download_file="${name}.tar.gz"
url="https://github.com/ocfbnj/${name}/releases/download/${version}/${download_file}"

start_file="/root/start.sh"
log_file="/root/ss.log"

default_port="5421"
default_password="ocfbnj"

echo "== ${name} ${version} =="

cd /root/
wget ${url}
tar -C /usr/local/bin -xzf ${download_file}

cat <<EOF > ${start_file}
#!/bin/sh
${name} -p ${default_port} -k ${default_password} 2>> ${log_file} &
EOF

chmod ug+x ${start_file}

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

systemctl daemon-reload
systemctl enable --now ${name}.service

echo "== Done =="
