#!/bin/bash

# create virtual environment
virtualenv --python=python3.6 venv_CREME

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

#chmod -R 775 ./
chmod -R 775 ./CREME_backend_execution/scripts

# create supper user
# runserver