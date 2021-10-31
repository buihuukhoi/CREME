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
send "cd ..\r"
expect "*>"
send "cd ..\r"
expect "*>"
send "cd ..\r"
expect "*>"
send "cd wireshark\r"
expect "*>"
send "dumpcap.exe -i 1 -P -w C:\\Users\\Public\\data\\traffic.pcap\r"
expect "*>"
send "exit\r"


