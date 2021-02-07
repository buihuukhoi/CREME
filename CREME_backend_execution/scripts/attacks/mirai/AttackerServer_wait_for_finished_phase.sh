#!/usr/bin/expect -f
# run at controller to wait until specific phase finished
set delKnownHosts [lindex $argv 0]
set CNC_ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set finishedPhaseFile [lindex $argv 5]
set flag 0

set timeout 10

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$CNC_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~# "
send "cat $path/$finishedPhaseFile\r"

while { $flag < 1 } {
    expect "True" {
	    incr flag
    }
    send "cat $path/$finishedPhaseFile\r"
    sleep 1
}

expect "*:~# "
send "exit\r"
