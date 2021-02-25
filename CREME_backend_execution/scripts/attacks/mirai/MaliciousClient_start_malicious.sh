#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set pids_file [lindex $argv 5]
set logs_path [lindex $argv 6]
set outputTime [lindex $argv 7]
#set malicious_file [lindex $argv 6]
set malicious_file "mirai.dbg"

set timeout 10

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# Record time_kali_start_scan.txt
set DATE [exec date +%s]
set outputTimeFile [open $logs_path/$outputTime "w+"]
puts $outputTimeFile $DATE
close $outputTimeFile

expect "*:~# " 
send "nohup $path/./$malicious_file &\r"
expect "output to 'nohup.out'"
send "\r"

expect "*:~# "
#send "ps -ef | grep '$path/./$malicious_file' | awk '{print \$2}' > $path/$pids_file\r"
send "ps -ef | grep 'mirai.dbg' | awk '{print \$2}' > $path/$pids_file\r"

expect "*:~# "
send "exit\r"
