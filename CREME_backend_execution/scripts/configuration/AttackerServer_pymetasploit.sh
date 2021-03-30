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

# install metasploit
expect "*:~# "
send "sudo apt install curl\r"
expect "*:~# "
send "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall \r"
expect "*:~# "
send "chmod +x msfinstall \r"
expect "*:~# "
send "sudo ./msfinstall \r"

# install python 3.8
expect "*:~# "
send "sudo add-apt-repository ppa:deadsnakes/ppa \r"
expect "to cancel adding it"
send "\r"
expect "*:~# "
send "sudo apt update \r"
expect "*:~# "
send "sudo apt install python3.8 -y \r"
expect "*:~# "
send "sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.5 1 \r"
expect "*:~# "
send "sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 2 \r"
expect "*:~# "
send "sudo apt install python3.8-distutils -y \r"
expect "*:~# "
send "sudo apt install python3-pip -y \r"
expect "*:~# "
send "sudo python3.8 -m easy_install pip \r"
expect "*:~# "
send "sudo apt remove python3-pip -y \r"
expect "*:~# "
send "sudo python3.8 -m easy_install pip \r"

# Pymetasploit (Py3)
expect "*:~# "
send "python3.8 -m pip install --user pymetasploit3 \r"

expect "*:~# "
send "exit\r"
