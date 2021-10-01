#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set kali_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set controller_ip [lindex $argv 4]
set controller_username [lindex $argv 5]
set controller_pass [lindex $argv 6]
set controller_path [lindex $argv 7]
set path "/root/Desktop"
set file [lindex $argv 8]

set timeout 30

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$kali_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

#config dns
expect "#"
send "rm ~/.ssh/known_hosts\r"
expect "#"
send "scp -r $controller_username@$controller_ip:$controller_path/$file $path\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"

expect "#"
send "exit\r"

