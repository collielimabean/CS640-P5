#!/bin/bash
if [ $# -eq 0 ]
  then
    echo "Usage: ./searchJSON <ip address>"
    exit
fi

ip=$1 

jq '.prefixes[] | select((.service=="EC2"))' < ip-ranges.json > tmp.txt
grep $ip tmp.txt

rm tmp.txt
