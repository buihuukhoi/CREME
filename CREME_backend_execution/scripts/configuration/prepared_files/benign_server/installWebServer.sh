#!/bin/bash

if [ $# != 2 ]; then
    echo "Usage: ./installWebServer.sh username domainname"
    exit -1
fi

USERNAME=$1
domainname=$2

apt-get update
apt-get install -y expect

###############################
# Uninstall MySQL and Apache2 #
###############################

apt-get purge -y mysql*
rm -rf /etc/mysql
rm -rf /var/lib/mysql
killall -9 mysqld
userdel mysql
service apache2 stop
apt-get purge -y apache2*
# apt-get purge -y php5*
apt-get autoremove -y
apt-get autoclean

###################
# install apache2 #
###################
apt-get install -y apache2
# systemctl enable apache2

echo "ServerName www.$domainname" >> /etc/apache2/apache2.conf
# systemctl restart apache2
service apache2 restart
ufw allow in 'Apache Full'

###################
# install mariadb #
###################
export DEBIAN_FRONTEND=noninteractive 
debconf-set-selections <<< 'mariadb-server-5.5 mysql-server/root_password password qsefthuk'
debconf-set-selections <<< 'mariadb-server-5.5 mysql-server/root_password_again password qsefthuk'
apt-get install -y mariadb-server mariadb-client

# systemctl enable mysql

# SECURE_MYSQL=$(expect -c "

# set timeout 3
# spawn mysql_secure_installation

# expect \"Enter current password for root (enter for none):\"
# send \"\r\"

# expect \"root password?\"
# send \"y\r\"

# expect \"New password:\"
# send \"qsefthuk\r\"

# expect \"Re-enter new password:\"
# send \"qsefthuk\r\"

# expect \"Remove anonymous users?\"
# send \"y\r\"

# expect \"Disallow root login remotely?\"
# send \"n\r\"

# expect \"Remove test database and access to it?\"
# send \"y\r\"

# expect \"Reload privilege tables now?\"
# send \"y\r\"

# expect eof
# ")

# echo "${SECURE_MYSQL}"

echo "update user set plugin='' where User='root'; flush privileges;" | mysql --defaults-file=/etc/mysql/debian.cnf mysql

mysql -u root -pqsefthuk << EOF
select now();
show variables like "%time_zone%";
set global time_zone = '+8:00';
set time_zone = '+8:00';
flush privileges;
EOF

###############
# install php #
###############
# DEBIAN_FRONTEND=noninteractive apt-get install -y php5-mysql php5 libapache2-mod-php5 php5-mcrypt
# a2enmod php5
# systemctl restart apache2
# service apache2 restart

######################
# install phpMyAdmin #
######################

export DEBIAN_FRONTEND=noninteractive

expect -c "

set timeout 100
spawn apt-get install -y phpmyadmin

expect \"*** php5.conf (Y/I/N/O/D/Z) \[default=N\] ? \"
send \"\r\"

expect eof
"

cp ./config_files/web/phpmyadmin.conf /etc/dbconfig-common/phpmyadmin.conf
dpkg-reconfigure --frontend=noninteractive phpmyadmin
echo "Include /etc/phpmyadmin/apache.conf" >> /etc/apache2/apache2.conf
# systemctl restart apache2
service apache2 restart

########################
# use website template #
########################

# download template
# wget -O zacson.zip 'https://colorlib.com/download/6639/?dlm-dp-dl-force=1&dlm-dp-dl-nonce=bdb6988b9f'
apt-get install -y software-properties-common
add-apt-repository -y ppa:fkrull/deadsnakes
apt-get update
apt-get install -y python3.5
wget -q -O - https://bootstrap.pypa.io/3.5/get-pip.py | python3.5
pip3 install gdown
gdown https://drive.google.com/uc?id=10hWuXEte-xlUE64_kOznOwDlEBxB4-oa
# sudo chown server:server zacson.zip
unzip zacson.zip -d zacson

# change /var/www/html group premission
find zacson/zacson -type d -print0 | xargs -0 chmod 0755
find zacson/zacson -type f -print0 | xargs -0 chmod 0644

rm -r /var/www/html/*
cp -r ./zacson/zacson/* /var/www/html
chown -R $USERNAME:www-data /var/www/html