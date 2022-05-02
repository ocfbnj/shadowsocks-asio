#!/bin/bash

# This script is used to generate chn.acl
# Usage: ./update_chn_acl_list.sh > ../acl/chn.acl 

CHINA_IP_LIST_URL="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"

bypass_list=`curl ${CHINA_IP_LIST_URL} -L`
last_update_time=`date -u "+%Y-%m-%d %H:%M:%S +0000 UTC"`

echo "# last update time: ${last_update_time}
[proxy_all]

[bypass_list]
${bypass_list}
"
