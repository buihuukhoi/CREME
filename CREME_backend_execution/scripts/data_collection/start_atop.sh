#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set client [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set folder [lindex $argv 4]
set atop_file [lindex $argv 5]
set interval [lindex $argv 6]
set atop_pids_file [lindex $argv 7]
set controller_ip [lindex $argv 8]
set controller_username [lindex $argv 9]
set controller_password [lindex $argv 10]
set controller_path [lindex $argv 11]

set startatop_file "startatop.sh"

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$client

expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~# "
send "rm $folder/$atop_file \r"

expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp -r $controller_username@$controller_ip:$controller_path/CREME/CREME_backend_execution/scripts/data_collection/prepared_files/$startatop_file $folder\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_password\r"

expect "*:~# "
send "chmod +x $folder/$startatop_file \r"
expect "*:~# "
send "nohup $folder/./$startatop_file $folder $atop_file $interval &\r"
expect "output to 'nohup.out'"
send "\r"

# Start capturing
#expect "*:~# "
#sleep 1
#atop -w /root/atop.raw 5 10
#send "nohup atop -a -w $folder/$atop_file $interval &\r"
#expect "output to 'nohup.out'"
#send "\r"

expect "*:~# "
send "ps -ef | grep './$startatop_file' | awk '{print \$2}' > $folder/$atop_pids_file\r"

#send "ps -ef | grep 'atop -a -w $folder/$atop_file $interval' | awk '{print \$2}' > $folder/$atop_pids_file\r"
send "ps -ef | grep 'atop -a -w $folder' | awk '{print \$2}' > $folder/$atop_pids_file\r"


expect "*:~# "
send "exit\r"
