#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set dataLoggerServer [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$dataLoggerServer
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# update time
expect "*:~# "
send "apt -y install ntp\r"
expect "*:~# "
send "apt -y install ntpdate\r"
expect "*:~# "
send "sudo ntpdate ntp.ubuntu.com\r"

expect "*:~# "
send "exit\r"
