#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]

set timeout 15

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*>"
send {logman create counter perf_log -c "\Process(*)\*" -si 1 -o c:\Users\Public\data\stat -v nnnnnn -f csv}
send \r
expect "*>"
send "logman start perf_log\r"
expect "*>"
send "exit\r"


