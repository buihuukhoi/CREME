#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]

set timeout 5

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*>"
send "net start w32time\r"
expect "*>"
send "w32tm /resync /force\r"
expect "*>"
send "cd Desktop\r"
expect "*>"
send "cd config_client\r"
expect "*>"
send "Wireshark-win64-3.4.0.exe /S\r"
expect "*>"
send "winpcap-nmap-4.13.exe /S\r"
expect "*>"
send "cd ..\r"
expect "*>"
send "cd ..\r"
expect "*>"
send "cd ..\r"
expect "*>"
send "cd Public\r"
expect "*>"
send "mkdir data\r"
expect "*>"
send "exit\r"


