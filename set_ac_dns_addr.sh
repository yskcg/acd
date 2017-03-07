#!/bin/sh

vaild_ip_flag=0
check_ip() {
    IP=$1
    VALID_CHECK=$(echo $IP|awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print "yes"}')
    if echo $IP|grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$">/dev/null; then
        if [ ${VALID_CHECK:-no} == "yes" ]; then
            vaild_ip_flag=1
        else
            vaild_ip_flag=0
        fi
    else
        vaild_ip_flag=0
    fi
}
#get the device address
addr=`ip -4 addr list dev br-lan | grep inet | awk '{print$2}' | cut -d / -f 1 | sed -e '/192.168.33.111/d'`
echo "address:${addr}"
check_ip ${addr}

if [ ${vaild_ip_flag} -eq 1 ];then
    echo "hello"
    pdnsd-ctl add a ${addr} www.morewifi.ac.com 86400
fi

