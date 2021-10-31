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

sleep 15

expect "*>"
send {copy "C:\Users\Public\Music\Sample Music\Kalimba.mp3" "C:\Users\Public\" }
send \r
expect "*>"
send "exit\r"
