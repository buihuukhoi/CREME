#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set dataLoggerServer [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set machine_ip [lindex $argv 4]
set machine_user [lindex $argv 5]
set machine_pass [lindex $argv 6]

set atop_folder_DLS "/home/dataloggerserver/All_data"
# example: ./download_atop_data.sh 192.168.1.164 root qsefthuk 192.168.1.112 root qsefthuk /root atop.raw /root 112_atop.raw

set timeout 15

# SSH connection
#spawn /bin/bash ./DelKnownHosts.sh
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$dataLoggerServer

expect "*continue connecting (yes/no*)? "
send "yes\r"

expect " password: "
send "$password\r"

# download the atop data from the machine in our system
expect "*:~$ "
send "rm ~/.ssh/known_hosts\r"
expect "*:~$ "
send "scp -r $machine_user@$machine_ip:/root/times $atop_folder_DLS\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$machine_pass\r"

expect "*:~$ "
send "exit\r"
