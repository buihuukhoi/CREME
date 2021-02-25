#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set vulnerableClient [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set server_ip [lindex $argv 4]

set timeout 120

# SSH connection
#spawn /bin/bash ./DelKnownHosts.sh
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$vulnerableClient

expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# mount filesystem /run with exec option  -Mirai will be at /run/a
expect "*:~# "
send "mount -o remount,exec /run\r"

expect "*:~# "
send "exit\r"
