#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set hostname [lindex $argv 1]
set ip [lindex $argv 2]
set username [lindex $argv 3]
set password [lindex $argv 4]
set folder [lindex $argv 5]
set controller_ip [lindex $argv 6]
set controller_user [lindex $argv 7]
set controller_pass [lindex $argv 8]
set controller_path [lindex $argv 9]
set domain_name [lindex $argv 10]
set attacker_server_ip [lindex $argv 11]

set timeout 1200

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# update time
expect "*:~# "
send "sudo apt update \r"
expect "*:~# "
send "apt -y install ntp\r"
expect "*:~# "
send "apt -y install ntpdate\r"
expect "*:~# "
send "sudo ntpdate ntp.ubuntu.com\r"


expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp -r $controller_user@$controller_ip:$controller_path/CREME/CREME_backend_execution/scripts/configuration/prepared_files/benign_server/* $folder\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"

expect "*:~# "
send "chmod +x *.sh\r"

# install DNS
expect "*:~# "
send "./installDNSServer.sh $domain_name $ip $attacker_server_ip\r"
expect "*:~# "
send "iptables -D INPUT -j DROP\r"
# install FTP
#expect "*:~# "
#send "./installFTPServer.sh\r"
# install Web Server
expect "*:~# "
send "./installWebServer.sh $hostname $domain_name\r"
# install email
expect "*:~# "
send "./installMailServer.sh $domain_name $ip $hostname\r"
# upload certificate to controller
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp certificates $controller_user@$controller_ip:$controller_path/CREME/CREME_backend_execution/scripts/configuration/prepared_files/benign_client/ConfigureFiles/certificates_$ip\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"

# restart rsyslog
expect "*:~# "
send "service rsyslog restart \r"


expect "*:~# "
send "exit\r"
