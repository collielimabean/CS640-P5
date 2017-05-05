import json
import sys
import socket
import struct

def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def is_match(ip_prefix, ip_list):
    split = ip_prefix.split('/')
    ip = ip2long(split[0])    
    prefix = int(split[1])
    mask = (~0) << (32 - prefix)

    ip_int = [ip2long(i) for i in ip_list]
    return any([(ip & mask) == (i & mask) for i in ip_int])


def single_match(ip_prefix, ip):
    split = ip_prefix.split('/')
    subnet = ip2long(split[0])    
    prefix = int(split[1])
    mask = (~0) << (32 - prefix)
    return (subnet & mask) == (ip2long(ip) & mask)



if len(sys.argv) != 3:
    print "usage: python search.py <json> <ip.txt>"
    exit()

json_file_name = sys.argv[1]
ip_file_name = sys.argv[2]


#print single_match("54.160.0.0/13", "54.164.218.218")
#print single_match("107.20.0.0/14", "107.23.146.34")

with open(json_file_name, 'r') as json_file:
    data = json.load(json_file)

    # get filtered subset
    filtered = data['prefixes']

    # open and read ip list
    with open(ip_file_name, 'r') as ip_file:
        ip_list = ip_file.readlines()

        for x in filtered:
            match = is_match(x['ip_prefix'], ip_list)
            if match:
                print str(x)




"""
[MATCH] Checking IP address 54.164.218.118 against subnet 54.160.0.0 with prefix 13
[MATCH] Checking IP address 107.23.146.34 against subnet 107.20.0.0 with prefix 14
[MATCH] Checking IP address 54.173.76.18 against subnet 54.172.0.0 with prefix 15
[MATCH] Checking IP address 54.173.236.168 against subnet 54.172.0.0 with prefix 15
[MATCH] Checking IP address 54.165.102.104 against subnet 54.160.0.0 with prefix 13
[MATCH] Checking IP address 54.236.175.171 against subnet 54.236.0.0 with prefix 15
[MATCH] Checking IP address 54.85.85.246 against subnet 54.80.0.0 with prefix 13
[MATCH] Checking IP address 54.89.43.47 against subnet 54.88.0.0 with prefix 14
"""
