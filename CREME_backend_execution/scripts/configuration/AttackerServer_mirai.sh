#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set controller_ip [lindex $argv 5]
set controller_user [lindex $argv 6]
set controller_pass [lindex $argv 7]
set controller_path [lindex $argv 8]
set transfer_pids [lindex $argv 9]

set cnc_config_path "CREME/scripts/prepared_files/mirai/cnc"

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# install expect
expect "*:~# "
send "apt -y install expect\r"

# download files
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp $controller_user@$controller_ip:$controller_path/$cnc_config_path/* $path\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"

expect "*:~# "
send "chmod +x $path/*\r"
expect "*:~# "
send "> $transfer_pids\r"

# build Mirai-Source-Code
# ?????????????????????????????????

expect "*:~# "
send "exit\r"
