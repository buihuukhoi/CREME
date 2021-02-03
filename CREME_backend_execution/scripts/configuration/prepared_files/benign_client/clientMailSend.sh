#!/bin/bash

if [ $# != 3 ]; then
    echo "Usage: ./clientMailSend.sh targetmailclient sleepsecount domainname"
    exit -1
fi

TARGETMAILCLIENT=$1
SLEEPSEC=$2
domainname=$3

TARGET="${TARGETMAILCLIENT}@mail.${domainname}"

while true; do
# send
echo "Hello, nice to meet you!" | mutt -s "Hi" ${TARGET}
sleep $SLEEPSEC
done