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
send "taskkill /IM virus_test.exe /F\r"
expect "*>"
send "SC DELETE virus_test\r"
expect "*>"
send "del C:\\Windows\\Temp\\virus_test.exe\r"
expect "*>"
send "exit\r"


