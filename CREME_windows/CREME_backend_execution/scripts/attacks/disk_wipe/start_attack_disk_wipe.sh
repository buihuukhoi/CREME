#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set kali_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path "/root/times"
set target_ip [lindex $argv 4]

set timeout 15

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$kali_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"


expect "*:~# "
send "python3 /root/Desktop/disk_wipe/disk_wipe_FirstStage.py $path $kali_ip $target_ip\r"

sleep 120

expect "#"
send "cd Desktop\r"

expect "*:~#"
send "exit\r"


