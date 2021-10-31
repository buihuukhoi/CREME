wget http://qosient.com/argus/src/argus-3.0.8.2.tar.gz
wget http://qosient.com/argus/src/argus-clients-3.0.8.2.tar.gz

tar -xvzf argus-3.0.8.2.tar.gz
tar -xvzf argus-clients-3.0.8.2.tar.gz

sudo apt-get update
sudo apt-get install flex -y
sudo apt-get install bison -y
sudo apt-get install libpcap-dev -y

cd argus-3.0.8.2
chmod +x configure
./configure
sudo make install

cd -

cd argus-clients-3.0.8.2
chmod +x configure
./configure
sudo make install

cd -