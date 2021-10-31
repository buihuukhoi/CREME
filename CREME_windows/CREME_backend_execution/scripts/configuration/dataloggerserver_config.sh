#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set dataLoggerServer_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]

set timeout 15

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$dataLoggerServer_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# update time
expect "*:~$ "
send "sudo apt -y install ntp\r"
expect "*: "
send "$password\r"
expect "*:~$ "
send "sudo apt -y install ntpdate\r"

expect "*:~$ "
send "sudo ntpdate ntp.ubuntu.com\r"

expect "*:~$ "
send "rm -rf All_data\r"
expect "*:~$ "
send "mkdir All_data\r"
expect "*:~$ "
send "mkdir -p All_data/traffic\r"
expect "*:~$ "
send "mkdir -p All_data/syslog\r"
expect "*:~$ "
send "mkdir -p All_data/accounting\r"

expect "*:~$ "
send "exit\r"

