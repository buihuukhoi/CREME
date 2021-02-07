#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set pids_file [lindex $argv 5]
#set pids_file "pids_file.txt"

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# Stop pids
expect "*:~# "
send "tmppid=\$(sed -n -e 1p $path/$pids_file)\r"
expect "*:~# "
send "tmpname=\$(ps -o cmd= \$tmppid)\r"
expect "*:~# "
send "tmpname=\$(echo \$tmpname | awk '{print \$1;}')\r"
expect "*:~# "
send "pkill -f \$tmpname\r"

expect "*:~# "
send "exit\r"
