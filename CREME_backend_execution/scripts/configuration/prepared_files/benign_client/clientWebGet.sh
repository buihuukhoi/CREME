#!/bin/bash

if [ $# != 2 ]; then
    echo "Usage: ./clientWebGet.sh sleepsecount domainname"
    exit -1
fi

apt-get install -y python3-pip
pip3 install requests2

SLEEPSEC=$1
domainname=$2

while true; do
# send
python3 getFromWeb.py $domainname
sleep $SLEEPSEC
done