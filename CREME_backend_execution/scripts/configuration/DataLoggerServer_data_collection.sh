#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set dataLoggerServer [lindex $argv 1]
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

spawn ssh $username@$dataLoggerServer
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# install and configure rsyslog remote for syslog collection
expect "*:~# "
send "apt update && apt install -y rsyslog\r"
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp $controller_user@$controller_ip:$controller_path/CREME/CREME_backend_execution/scripts/configuration/prepared_files/rsyslog_server/rsyslog.conf /etc/\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"
expect "*:~# "
send "systemctl restart rsyslog\r"

# install tcpdump for Network Packets colection
expect "*:~# "
send "apt update && apt -y install tcpdump\r"

# install atop to process atop data from other machines
expect "*:~# "
send "apt update && apt install atop\r"

expect "*:~# "
send "exit\r"
