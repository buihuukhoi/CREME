#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set client_hostname [lindex $argv 4]
set client_password [lindex $argv 5]

set timeout 120

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# create ftp user
expect "*:~# "
send "./createFTPUserAccount.sh $client_hostname $client_password\r"

expect "*:~# "
send "exit\r"
