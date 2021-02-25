#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set client_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set datalogger_ip [lindex $argv 4]

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$client_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# forward sending packet to DataLoggerServer
# configure Port Mirroring for Network Packets colection
expect "*:~# "
send "iptables -t mangle -D POSTROUTING -j TEE --gateway $datalogger_ip\r"
expect "*:~# "
send "iptables -t mangle -I POSTROUTING -j TEE --gateway $datalogger_ip\r"
# iptables-persistent
expect "*:~# "
send "DEBIAN_FRONTEND=noninteractive apt -y install iptables-persistent\r"
expect "*:~# "
send "iptables-save > /etc/iptables/rules.v4\r"

# update time
expect "*:~# "
send "systemctl stop ntp\r"
expect "*:~# "
send "sudo ntpdate ntp.ubuntu.com\r"
expect "*:~# "
send "systemctl restart ntp\r"

# exit
expect "*:~# "
send "exit\r"
