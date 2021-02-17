#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set dataLoggerServer [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set machine_ip [lindex $argv 4]
set machine_user [lindex $argv 5]
set machine_pass [lindex $argv 6]
set atop_folder [lindex $argv 7]
set atop_file [lindex $argv 8]
set atop_folder_DLS [lindex $argv 9]
set new_atop_file [lindex $argv 10]
# example: ./download_log_data.sh 192.168.1.164 root qsefthuk 192.168.1.112 root qsefthuk /root atop.raw /root 112_atop.raw

set timeout 120

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
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp $machine_user@$machine_ip:$atop_folder/$atop_file $atop_folder_DLS\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$machine_pass\r"

expect "*:~# "
send "mv $atop_folder_DLS/$atop_file $atop_folder_DLS/$new_atop_file\r"

expect "*:~# "
send "exit\r"
