#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set collectuser [lindex $argv 4]
set collect_ip [lindex $argv 5]
set collect_password [lindex $argv 6]


set timeout 10

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~$ "
send "rm ~/.ssh/known_hosts\r"

expect "*:~$ "
send "mkdir -p All_data/$collectuser\r"
expect "*:~$ "
send "scp -r $collectuser@$collect_ip:/home/Public/data /home/$username/All_data/$collectuser \r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$collect_password\r"
expect "*:~$ "
send "exit\r"


