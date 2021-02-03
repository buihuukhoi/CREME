#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set hostname [lindex $argv 1]
set ip [lindex $argv 2]
set username [lindex $argv 3]
set password [lindex $argv 4]
set folder [lindex $argv 5]
set ftp_folder [lindex $argv 6]
set target_virtual_account [lindex $argv 7]
set sleep_second [lindex $argv 8]
set benign_pids_file [lindex $argv 9]
set domain_name [lindex $argv 10]

set timeout 120

# SSH connection
#spawn /bin/bash ./DelKnownHosts.sh
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~# "
send "mkdir $folder/$ftp_folder\r"

# execute ftp in the backend
expect "*:~# "
send "nohup ./clientFtpDownloadUpload.sh $hostname $password $folder/$ftp_folder $sleep_second $domain_name &\r"
expect "output to 'nohup.out'"
send "\r"

# execute mail in the backend
expect "*:~# "
send "nohup ./clientMailSend.sh $target_virtual_account $sleep_second $domain_name &\r"
expect "output to 'nohup.out'"
send "\r"
#./clientMailSend.sh target_virtual_account sleep_second

# execute web in the backend
expect "*:~# "
send "nohup ./clientWebGet.sh $sleep_second $domain_name &\r"
expect "output to 'nohup.out'"
send "\r"

expect "*:~# "
send "ps -ef | grep 'clientFtpDownloadUpload.sh' | awk '{print \$2}' > $folder/$benign_pids_file\r"
expect "*:~# "
send "ps -ef | grep 'clientMailSend.sh' | awk '{print \$2}' >> $folder/$benign_pids_file\r"
expect "*:~# "
send "ps -ef | grep 'clientWebGet.sh' | awk '{print \$2}' >> $folder/$benign_pids_file\r"

expect "*:~# "
send "exit\r"
