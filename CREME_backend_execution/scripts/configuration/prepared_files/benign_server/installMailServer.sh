#!/bin/bash

if [ $# != 3 ]; then
    echo "Usage: ./installMailServer.sh domainname(eq:speedlab.net) ip hostname"
    exit -1
fi

# preprocessing configure file first
domainname=$1
ip=$2
hostname=$3

cp ./config_files/mail/hosts_sample ./config_files/mail/hosts
sed -i "s/XXDOMAINXX/${domainname}/g" ./config_files/mail/hosts
sed -i "s/XXIPXX/${ip}/g" ./config_files/mail/hosts
sed -i "s/XXHOSTXX/${hostname}/g" ./config_files/mail/hosts

cp ./config_files/mail/main_sample ./config_files/mail/main.cf
sed -i "s/XXDOMAINXX/${domainname}/g" ./config_files/mail/main.cf

cp ./config_files/mail/dovecot_sample ./config_files/mail/dovecot.conf
sed -i "s/XXDOMAINXX/${domainname}/g" ./config_files/mail/dovecot.conf

echo "mail.${domainname}" > /etc/mailname

####################################

hostnamectl set-hostname $hostname
cp ./config_files/mail/hosts /etc/hosts

apt-get update
apt-get install -y expect
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql


################################
# Part1 - Create User Database #
################################

mysql -u root -pqsefthuk << EOF
CREATE USER dba@localhost IDENTIFIED BY 'qsefthuk';
GRANT ALL PRIVILEGES ON * . * TO dba@localhost;
FLUSH PRIVILEGES;
EOF

mysql -u dba -pqsefthuk << EOF
CREATE DATABASE EmailServer_db;
USE EmailServer_db;
CREATE TABLE \`Domains_tbl\` ( 
    \`DomainId\` INT NOT NULL AUTO_INCREMENT, 
    \`DomainName\` VARCHAR(50) NOT NULL, 
    PRIMARY KEY (\`DomainId\`)
) ENGINE = InnoDB;
CREATE TABLE \`Users_tbl\` ( 
    \`UserId\` INT NOT NULL AUTO_INCREMENT,  
    \`DomainId\` INT NOT NULL,  
    \`password\` VARCHAR(106) NOT NULL,  
    \`Email\` VARCHAR(100) NOT NULL,  
    PRIMARY KEY (\`UserId\`),  
    UNIQUE KEY \`Email\` (\`Email\`),  
    FOREIGN KEY (DomainId) REFERENCES Domains_tbl(DomainId) ON DELETE CASCADE 
) ENGINE = InnoDB;
CREATE TABLE \`Alias_tbl\` (
    \`AliasId\` INT NOT NULL AUTO_INCREMENT, 
    \`DomainId\` INT NOT NULL, 
    \`Source\` varchar(100) NOT NULL, 
    \`Destination\` varchar(100) NOT NULL, 
    PRIMARY KEY (\`AliasId\`), 
    FOREIGN KEY (DomainId) REFERENCES Domains_tbl(DomainId) ON DELETE CASCADE
) ENGINE = InnoDB;

INSERT INTO Domains_tbl (DomainName) VALUES ('mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client1@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client2@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client3@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client4@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client5@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client6@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client7@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client8@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client9@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client10@mail.$domainname');

INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client100@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client101@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client102@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client103@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client104@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client105@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client106@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client107@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client108@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client109@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client110@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client111@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client112@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client113@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client114@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client115@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client116@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client117@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client118@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client119@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client120@mail.$domainname');

INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client210@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client211@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client212@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client213@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client214@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client215@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client216@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client217@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client218@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client219@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client220@mail.$domainname');
EOF

#####################################
# Part 2 - Config postfix & dovecot #
#####################################

# config postfix
cp ./config_files/mail/main.cf /etc/postfix/main.cf
cp ./config_files/mail/master.cf /etc/postfix/master.cf
cp ./config_files/mail/mariadb-vdomains.cf /etc/postfix/mariadb-vdomains.cf
cp ./config_files/mail/mariadb-vusers.cf /etc/postfix/mariadb-vusers.cf
cp ./config_files/mail/mariadb-valias.cf /etc/postfix/mariadb-valias.cf
chmod 640 /etc/postfix/mariadb-vdomains.cf
chmod 640 /etc/postfix/mariadb-vusers.cf
chmod 640 /etc/postfix/mariadb-valias.cf
chown root:postfix /etc/postfix/mariadb-vdomains.cf
chown root:postfix /etc/postfix/mariadb-vusers.cf
chown root:postfix /etc/postfix/mariadb-valias.cf

expect -c "

set timeout 3
spawn openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/ssl-cert-snakeoil.pem

expect \"Country Name (2 letter code) \[AU\]:\"
send \"TW\r\"

expect \"State or Province Name (full name) \[Some-State\]:\"
send \"Taiwan\r\"

expect \"Locality Name (eg, city) \[\]:\"
send \"Hsinchu\r\"

expect \"Organization Name (eg, company) \[Internet Widgits Pty Ltd\]:\"
send \"NCTU\r\"

expect \"Organizational Unit Name (eg, section) \[\]:\"
send \"High Speed Network Lab\r\"

expect \"Common Name (e.g. server FQDN or YOUR name) \[\]:\"
send \"mail.$domainname\r\"

expect \"Email Address \[\]:\"
send \"\r\"

expect eof
"

cp /etc/ssl/certs/ssl-cert-snakeoil.pem ./certificates

# config dovecot
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /home/vmail -m
cp ./config_files/mail/dovecot.conf /etc/dovecot/dovecot.conf
cp ./config_files/mail/10-auth.conf /etc/dovecot/conf.d/10-auth.conf
cp ./config_files/mail/auth-sql.conf.ext /etc/dovecot/conf.d/auth-sql.conf.ext
cp ./config_files/mail/10-mail.conf /etc/dovecot/conf.d/10-mail.conf
cp ./config_files/mail/10-master.conf /etc/dovecot/conf.d/10-master.conf
cp ./config_files/mail/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf
cp ./config_files/mail/dovecot-sql.conf.ext /etc/dovecot/dovecot-sql.conf.ext
cp ./config_files/mail/10-logging.conf /etc/dovecot/conf.d/10-logging.conf

cp /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/private/dovecot.key
cp /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/ssl/certs/dovecot.pem

chown vmail:dovecot /var/log/dovecot.log
chmod 660 /var/log/dovecot.log
chown -R vmail:vmail /home/vmail
chown -R vmail:dovecot /etc/dovecot 
chmod -R o-rwx /etc/dovecot

ufw allow 143/tcp
ufw allow 110/tcp
ufw allow 587/tcp

# systemctl stop postfix
# systemctl stop dovecot
# systemctl start dovecot
# systemctl start postfix
service postfix stop
service dovecot stop
service dovecot start
service postfix start