#!/bin/bash

# install python 3.6
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt-get update
sudo apt-get install python3.6 -y

sudo apt-get update
sudo apt-get install expect -y

# virtual environment
sudo apt-get install python-virtualenv -y

# install ssh server
sudo apt-get install openssh-server -y
