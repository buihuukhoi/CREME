#!/bin/bash

if [ $# != 3 ]; then
    echo "Usage: ./installDNSServer.sh domainname(eq:speedlab.net) ip cncip"
    exit -1
fi

# preprocessing configure file first
domainname=$1
ip=$2
cncip=$3
reverse_ip=`echo $ip | awk -F . '{print $4"."$3"."$2"."$1".in-addr.arpa"}'`

cp ./config_files/dns/dnsmasq_sample ./config_files/dns/dnsmasq.conf
sed -i "s/XXDOMAINXX/${domainname}/g" ./config_files/dns/dnsmasq.conf
sed -i "s/XXIPXX/${ip}/g" ./config_files/dns/dnsmasq.conf
sed -i "s/XXCNCIPXX/${cncip}/g" ./config_files/dns/dnsmasq.conf
sed -i "s/XXREVERSEIPXX/${reverse_ip}/g" ./config_files/dns/dnsmasq.conf

####################################

rm /etc/dnsmasq.conf
apt-get update
apt-get install -y dnsmasq
cp ./config_files/dns/dnsmasq.service /lib/systemd/system/dnsmasq.service
# systemctl enable dnsmasq

cp ./config_files/dns/dnsmasq.conf /etc/dnsmasq.conf
# systemctl restart dnsmasq
service dnsmasq restart
update-rc.d dnsmasq defaults
