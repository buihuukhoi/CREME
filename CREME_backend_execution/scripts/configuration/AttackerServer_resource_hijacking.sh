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
set prepared_files [lindex $argv 9]

#set prepared_files "CREME/CREME_backend_execution/scripts/configuration/prepared_files/disk_wipe/attacker_server"

set timeout 1200

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# download files
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp $controller_user@$controller_ip:$controller_path/$prepared_files/* $path\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"

expect "*:~# "
send "chmod +x $path/* \r"
expect "*:~# "
send "tar -xvzf $path/xmrig-6.5.0-linux-static-x64.tar.gz -C $path \r"

expect "*:~# "
send "mv $path/xmrig-6.5.0/xmrig /var/www/html/downloads\r"
expect "*:~# "
send "mv $path/xmrig-6.5.0/config.json /var/www/html/downloads\r"
expect "*:~# "
send "mv $path/xmrig-6.5.0/SHA256SUMS /var/www/html/downloads\r"

expect "*:~# "
send "exit\r"
