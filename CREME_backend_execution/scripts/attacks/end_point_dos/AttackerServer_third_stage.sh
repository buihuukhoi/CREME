#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set target_server_ip [lindex $argv 5]
set new_user_account [lindex $argv 6]
set new_user_password [lindex $argv 7]

set timeout 1200

set timestamp_folder "CREME_backend_execution/logs/rootkit_ransomware/times"
set outputTime "time_stage_3_start.txt"

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~# "
send "rm /root/.ssh/known_hosts \r"

set DATE [exec date +%s]
set outputTimeFile [open $timestamp_folder/$outputTime "w+"]
puts $outputTimeFile $DATE
close $outputTimeFile

expect "*:~# "
send "$path/./end_point_dos_ThirdStage.sh $target_server_ip $new_user_account $new_user_password \r"

expect "*:~# "
send "exit\r"
