#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set target_server_ip [lindex $argv 5]
set flag_finish [lindex $argv 6]

set timeout 1200

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"


expect "*:~# "
send "python3 $path/WipeDisk.py $path $ip $target_server_ip $flag_finish\r"

expect "$flag_finish"
send "\r"

expect "*:~# "
send "exit\r"