#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set folder [lindex $argv 4]
set atop_pids_file [lindex $argv 5]

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
send "ps -ef | grep 'atop -a -w $folder' | awk '{print \$2}' >> $folder/$atop_pids_file\r"

# Stop capturing
expect "*:~# "
#send "kill -9 \$(cat $folder/$atop_pids_file)\r"
send "kill -15 \$(cat $folder/$atop_pids_file)\r"

expect "*:~# "
send "exit\r"
