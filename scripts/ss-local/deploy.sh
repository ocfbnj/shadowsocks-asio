#!/bin/bash

name="shadowsocks-asio"
version="v0.0.4-alpha"

download_file="${name}.tar.gz"
url="https://github.com/ocfbnj/${name}/releases/download/${version}/${download_file}"

ss_local_start_file="/etc/${name}/ss-local.sh"
ss_local_log_file="/var/log/${name}/ss-local.log"
ss_local_service_name="ss-local.service"
ss_local_service_file="/etc/systemd/system/${ss_local_service_name}"

default_host="ocfbnj.cn"
default_remote_port="5421"
default_local_port="1080"
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
cat <<EOF > ${ss_local_start_file}
#!/bin/sh
${name} --Client -s ${default_host} -p ${default_remote_port} \
    -l ${default_local_port} -k ${default_password} >> ${ss_local_log_file} &
EOF

chmod ug+x ${ss_local_start_file}

# 4. Create service.
cat <<EOF > ${ss_local_service_file}
[Unit]
Description=${name} local server
After=network.target

[Service]
Type=forking
ExecStart=${ss_local_start_file}

[Install]
WantedBy=default.target
EOF

# 5. Start service.
systemctl daemon-reload
systemctl enable --now ${ss_local_service_name}

# 6. Clean up.
rm /root/${download_file}

echo "== Done =="
