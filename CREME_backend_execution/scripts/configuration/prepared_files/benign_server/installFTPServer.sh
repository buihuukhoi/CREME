#!/bin/bash

apt-get update
apt-get install -y expect vsftpd

ufw allow 20/tcp
ufw allow 21/tcp
ufw allow 40000:50000/tcp


cp ./config_files/ftp/vsftpd.conf /etc/vsftpd.conf
cp ./config_files/ftp/vsftpd.userlist /etc/vsftpd.userlist
service vsftpd restart
update-rc.d vsftpd defaults