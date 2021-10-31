#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set controller_path  [lindex $argv 4]

set timeout 5

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn scp -r $controller_path/CREME_backend_execution/scripts/configuration/config_client $username@$ip:/home/$username/Desktop/
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~$ "
send "exit\r"


