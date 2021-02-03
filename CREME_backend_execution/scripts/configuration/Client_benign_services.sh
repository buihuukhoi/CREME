#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set hostname [lindex $argv 1]
set ip [lindex $argv 2]
set username [lindex $argv 3]
set password [lindex $argv 4]
set folder [lindex $argv 5]
set ftp_folder [lindex $argv 6]
set controller_ip [lindex $argv 7]
set controller_user [lindex $argv 8]
set controller_pass [lindex $argv 9]
set controller_path [lindex $argv 10]
set server_ip [lindex $argv 11]
set virtual_account [lindex $argv 12]
set domain_name [lindex $argv 13]

set ConfigureFiles "ConfigureFiles"

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# download configured file from controller
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp -r $controller_user@$controller_ip:$controller_path/Creme/scripts/configuration/prepared_files/benign_client/*  $folder\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"
# add executable permission
expect "*:~# "
send "chmod +x *.sh\r"

# config new dns server
expect "*:~# "
send "cp $ConfigureFiles/resolv.conf /etc\r"
expect "*:~# "
send "sed -i \"s/my_dns_1/$server_ip/g\" /etc/resolv.conf\r"

# configure vulnerable services
# install and configure non-vulnerable telnet

# download config files from controller
# add executable permission
#chmod +x *.sh

# config mail client

expect "*:~# "
send "sudo apt update \r"
expect "*:~# "
send "./clientMailInstall.sh $virtual_account $hostname $domain_name $ConfigureFiles $server_ip \r"

# execute ftp in the backend
#./clientFtpDownloadUpload.sh hostname password local_folder sleep_second
# save pids to kill late

# execute mail in the backend
#./clientMailSend.sh target_virtual_account sleep_second

expect "*:~# "
send "exit\r"
