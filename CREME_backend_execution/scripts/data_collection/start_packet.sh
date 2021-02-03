#!/usr/bin/expect -f
set delKnownHosts [lindex $argv 0]
set dataLoggerServer [lindex $argv 1]
set username [lindex $argv 2]
set password [lindex $argv 3]
set path [lindex $argv 4]
set tcpFile [lindex $argv 5]
set netInterface [lindex $argv 6]
set tcp_pids_file [lindex $argv 7]
# example: ./start_packet.sh ./DelKnownHosts.sh 192.168.1.164 root qsefthuk /root/tcpdump_data.pcap enp3s0 /root/tcp_pids.txt

set timeout 120

# SSH connection
#spawn /bin/bash ./DelKnownHosts.sh
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$dataLoggerServer

expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# clean all pcap files before capturing
expect "*:~# "
send "rm $path/*.pcap\r"

# Start capturing
expect "*:~# "
#sudo tcpdump -w /root/mirai.pcap -n -i enp3s0 &
send "nohup tcpdump -U -w $path/$tcpFile -n -i $netInterface &\r"
expect "output to 'nohup.out'"
send "\r"

expect "*:~# "
#send "ps -ef | grep tcpdump | awk '{print $2}' > /root/tcp_pids.txt"
send "ps -ef | grep 'tcpdump -U -w' | awk '{print \$2}' > $path/$tcp_pids_file\r"

expect "*:~# "
send "exit\r"
