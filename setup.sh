#!/bin/bash

sudo apt-get install git -y
sudo apt-get install expect -y

git clone https://github.com/buihuukhoi/CREME.git

# create virtual environment
cd CREME
sudo apt-get install python3.6-venv python3.6-dev
python3.6 -m venv venv_CREME
# active venv
source venv_CREME/bin/activate

# update pip
pip install --upgrade pip

# install libraries
pip install -r requirements.txt

# create database
python manage.py migrate
python manage.py makemigrations CREMEapplication
python manage.py migrate

# create supper user
# runserver
