#!/bin/sh

sudo kill $(ps aux |grep 'python dnsServer.py' |awk '{print $2}')
sudo python dnsServer.py > log/dnsOut.txt &
sudo kill $(ps aux |grep 'python httpserver.py' |awk '{print $2}')
sudo python httpserver.py >log/httpserverOut.txt &
sudo kill $(ps aux |grep 'python client.py' |awk '{print $2}')
sudo python client.py >log/clientOut.txt &
sudo python attacker.py 
