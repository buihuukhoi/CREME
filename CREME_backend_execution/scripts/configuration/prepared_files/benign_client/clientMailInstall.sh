#!/bin/bash

if [ $# != 5 ]; then
    echo "Usage: ./clientMail.sh mailclientname hostname domainname configpath serverip, eq: ./clientMail.sh client118 benignclient1 speedlab.net ConfigureFiles 192.168.1.10"
    exit -1
fi

MAILUSERNAME=$1
HOSTNAME=$2
domainname=$3
configpath=$4
serverip=$5

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y mutt

mkdir ~/.mutt
cp ${configpath}/certificates_${serverip} ~/.mutt/certificates
cp muttrc_sample ~/.muttrc
sed -i "s/XXX/${MAILUSERNAME}/g" ~/.muttrc
sed -i "s/YYY/${domainname}/g" ~/.muttrc
chown -R ${HOSTNAME}:${HOSTNAME} ~/.mutt ~/.muttrc