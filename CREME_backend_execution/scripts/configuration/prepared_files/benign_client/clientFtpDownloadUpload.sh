#!/bin/bash

if [ $# != 5 ]; then
    echo "Usage: ./clientFtpDownloadUpload.sh username password folderpath sleepsecount domainname(eq:speedlab.net)"
    exit -1
fi

USER=$1
PASSWD=$2
FOLDERPATH=$3
SLEEPSEC=$4
HOST=$5

while true; do
# download
ftp -in $HOST << EOF
user $USER $PASSWD
binary
lcd $FOLDERPATH
cd ftp/files
mget *
quit
EOF

# sleep $SLEEPSEC

# upload
ftp -in $HOST << EOF
user $USER $PASSWD
binary
lcd $FOLDERPATH
cd ftp/files
mdelete *
mput *
quit
EOF

sleep $SLEEPSEC
done
