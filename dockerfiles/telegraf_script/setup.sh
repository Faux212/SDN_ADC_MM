
#!bin/bash
echo "#####INSTALLING DEPENDENCIES#####"
apt-get update
echo "#####Installing Python 2.7#####"
#yum install python 2.7 -y
apt-get install python 2.7 -y
echo "#####Installing sshpass#####"
apt-get install sshpass -y
#yum install sshpass -y
echo "#####Installing Python Pip#####"
#yum install python-pip -y
apt-get install python-pip -y
echo "#####Installing Pip Packages from requirements.txt#####"
pip install -r /home/requirements.txt

exec echo "DONE"
