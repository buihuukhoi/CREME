#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set client_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set controller_ip [lindex $argv 4]
set controller_user [lindex $argv 5]
set controller_pass [lindex $argv 6]
set controller_path [lindex $argv 7]
set server_ip [lindex $argv 8]

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$client_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# update time
expect "*:~# "
send "apt update\r"
expect "*:~# "
send "apt -y install ntp\r"
expect "*:~# "
send "apt -y install ntpdate\r"
expect "*:~# "
send "sudo ntpdate ntp.ubuntu.com\r"

# config new dns
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp -r $controller_user@$controller_ip:$controller_path/CREME/CREME_backend_execution/scripts/configuration/prepared_files/benign_client/ConfigureFiles/resolv.conf  /etc\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"
# add executable permission
expect "*:~# "
send "chmod +x /etc/resolv.conf\r"
expect "*:~# "
send "sed -i \"s/my_dns_1/$server_ip/g\" /etc/resolv.conf\r"

# exit
expect "*:~# "
send "exit\r"
