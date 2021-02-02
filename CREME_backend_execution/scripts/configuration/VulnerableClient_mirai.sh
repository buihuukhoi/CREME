#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set vulnerableClient [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set controller_ip [lindex $argv 4]
set controller_user [lindex $argv 5]
set controller_pass [lindex $argv 6]
set controller_path [lindex $argv 7]

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$vulnerableClient

expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# config new dns server
#expect "*:~# "
#send "cp ConfigureFiles/resolv.conf /etc\r"
#expect "*:~# "
#send "sed -i \"s/my_dns_1/$server_ip/g\" /etc/resolv.conf\r"

# configure vulnerable services
# install and configure vulnerable telnet
expect "*:~# "
send "apt update && apt -y install telnetd\r"
# download config file from controller
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp $controller_user@$controller_ip:$controller_path/CREME/CREME_backend_execution/scripts/configuration/prepared_files/telnet/securetty  /etc/\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"
# mount filesystem /run with exec option  -Mirai will be at /run/a
expect "*:~# "
send "mount -o remount,exec /run\r"

# ***** note: reboot will reset the mount noexec problem. How to deal?
# reboot
expect "*:~# "
send "reboot\r"

# must have 'expect eof' or 'interact' after send "reboot\r"
expect eof

# exit
#expect "*:~# "
#send "exit\r"
