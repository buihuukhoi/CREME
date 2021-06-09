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
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client11@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client12@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client13@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client14@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client15@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client16@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client17@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client18@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client19@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client20@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client21@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client22@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client23@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client24@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client25@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client26@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client27@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client28@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client29@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client30@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client31@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client32@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client33@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client34@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client35@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client36@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client37@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client38@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client39@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client40@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client41@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client42@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client43@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client44@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client45@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client46@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client47@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client48@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client49@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client50@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client51@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client52@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client53@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client54@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client55@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client56@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client57@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client58@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client59@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client60@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client61@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client62@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client63@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client64@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client65@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client66@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client67@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client68@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client69@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client70@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client71@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client72@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client73@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client74@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client75@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client76@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client77@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client78@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client79@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client80@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client81@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client82@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client83@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client84@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client85@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client86@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client87@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client88@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client89@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client90@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client91@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client92@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client93@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client94@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client95@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client96@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client97@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client98@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client99@mail.$domainname');

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
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client121@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client122@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client123@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client124@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client125@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client126@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client127@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client128@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client129@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client130@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client131@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client132@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client133@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client134@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client135@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client136@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client137@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client138@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client139@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client140@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client141@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client142@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client143@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client144@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client145@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client146@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client147@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client148@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client149@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client150@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client151@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client152@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client153@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client154@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client155@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client156@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client157@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client158@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client159@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client160@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client161@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client162@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client163@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client164@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client165@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client166@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client167@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client168@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client169@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client170@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client171@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client172@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client173@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client174@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client175@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client176@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client177@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client178@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client179@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client180@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client181@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client182@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client183@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client184@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client185@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client186@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client187@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client188@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client189@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client190@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client191@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client192@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client193@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client194@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client195@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client196@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client197@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client198@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client199@mail.$domainname');

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
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client221@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client222@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client223@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client224@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client225@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client226@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client227@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client228@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client229@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client230@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client231@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client232@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client233@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client234@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client235@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client236@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client237@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client238@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client239@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client240@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client241@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client242@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client243@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client244@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client245@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client246@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client247@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client248@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client249@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client250@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client251@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client252@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client253@mail.$domainname');
INSERT INTO Users_tbl (DomainId, password, Email) VALUES (1, ENCRYPT('qsefthuk', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), 'client254@mail.$domainname');
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