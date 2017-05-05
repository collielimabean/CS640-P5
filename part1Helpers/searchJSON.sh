#!/bin/bash
if [ $# -eq 0 ]
  then
    echo "Usage: ./searchJSON <ip address> (optional)<verbose>"
    exit
fi

ip=$1 
verbose=$2

jq '.prefixes[] | select((.service=="EC2"))' < ip-ranges.json > tmp.txt
if [ $verbose ]
then
  grep $ip -B 1 -A 3 tmp.txt
else
  grep $ip tmp.txt
fi
rm tmp.txt
