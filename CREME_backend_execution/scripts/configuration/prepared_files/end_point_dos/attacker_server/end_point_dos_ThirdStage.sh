#!/usr/bin/expect -f
set ip [lindex $argv 0]
set username [lindex $argv 1]
set password [lindex $argv 2]

set timeout 90

set sleep_time 60

# SSH connection
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "$ "
send "/bin/bash \r"

# TODO: tmp solution to limit number of process for the user,
# because ulimit can't be applied to ssh session.
# If we can apply ulimit setting to ssh session,
# this tmp solution can be removed
expect "$ "
send "ulimit -u 500 \r"

expect "$ "
send ":(){ :|: &};: \r"

expect "$ "
sleep $sleep_time
send "exit\r"
