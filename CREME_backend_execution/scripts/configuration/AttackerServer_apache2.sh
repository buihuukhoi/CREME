#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]


set timeout 1200

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~# "
send "sudo apt install apache2 -y\r"
expect "*:~# "
send "mv /etc/apache2/sites-enabled/000-default.conf /etc/apache2/sites-enabled/000-default.conf.old\r"
expect "*:~# "
send "mv /etc/apache2/sites-enabled/default-ssl.conf /etc/apache2/sites-enabled/default-ssl.conf.old\r"

expect "*:~# "
send "mkdir /var/www/html/downloads\r"

expect "*:~# "
send "service apache2 restart\r"

expect "*:~# "
send "exit\r"
