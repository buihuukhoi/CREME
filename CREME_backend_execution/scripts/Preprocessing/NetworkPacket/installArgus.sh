wget http://qosient.com/argus/src/argus-3.0.8.2.tar.gz
wget http://qosient.com/argus/src/argus-clients-3.0.8.2.tar.gz

tar -xvzf argus-3.0.8.2.tar.gz
tar -xvzf argus-clients-3.0.8.2.tar.gz

cd argus-3.0.8.2
chmod +x configure
./configure
make install

cd -

cd argus-clients-3.0.8.2
chmod +x configure
./configure
make install