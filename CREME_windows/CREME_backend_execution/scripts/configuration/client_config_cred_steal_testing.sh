#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set ip "192.168.1.110"
set username "testbed_2"
set password "qsefthuk"

set timeout 5

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn scp -r /home/controller/Desktop/scripts/configuration/config_client $username@$ip:/home/$username/Desktop/
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"


spawn ssh $username@$ip
expect " password: "
send "$password\r"

expect "*>"
send "net start w32time\r"
expect "*>"
send "cd Desktop\r"
expect "*>"
send "cd config_client\r"
#expect "*>"
#send "Wireshark-win64-3.4.0.exe /S\r"
#expect "*>"
#send "winpcap-nmap-4.13.exe /S\r"
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


