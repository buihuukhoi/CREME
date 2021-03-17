#!/bin/bash

if [ $# != 2 ]; then
    echo "Usage: ./createFTPUserAccount.sh username password"
    exit -1
fi

USERNAME=$1
PASSWD=$2

expect -c "

set timeout 3
spawn adduser ${USERNAME}

expect \"Enter new UNIX password:\"
send \"${PASSWD}\r\"

expect \"Retype new UNIX password:\"
send \"${PASSWD}\r\"

expect \"Full Name []:\"
send \"\r\"

expect \"Room Number []:\"
send \"\r\"

expect \"Work Phone []:\"
send \"\r\"

expect \"Home Phone []:\"
send \"\r\"

expect \"Other []:\"
send \"\r\"

expect \"Is the information correct? \[Y/n\]\"
send \"y\r\"

expect eof
"

mkdir /home/${USERNAME}/ftp
chown nobody:nogroup /home/${USERNAME}/ftp
chmod a-w /home/${USERNAME}/ftp
mkdir /home/${USERNAME}/ftp/files
chown ${USERNAME}:${USERNAME} /home/${USERNAME}/ftp/files

echo "vsftpd test file" | tee /home/${USERNAME}/ftp/files/test.txt
