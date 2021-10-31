#!/usr/bin/expect -f

set delKnownHosts [lindex $argv 0]
set ip [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]

set timeout 45

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*>"
send "wevtutil epl Security C:\\Users\\Public\\Sec_log.evtx\r"
expect "*>"
send "wevtutil epl System C:\\Users\\Public\\Sys_log.evtx\r"
expect "*>"
send "cd desktop\r"
expect "*>"
send "cd config_client\r"
expect "*>"
send "cd EvtxExplorer\r"
expect "*>"
send ".\\EvtxECmd.exe\r"
expect "*>"
send "evtxecmd.exe -d C:\\Users\\Public --csv C:\\Users\\Public\\data\\ --csvf log_out.csv\r"
expect "*>"
send "exit\r"


