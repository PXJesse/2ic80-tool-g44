# Util

# This file contains utility functions, classes and other structures which are used at different
# places in this tool.

import os
import ipaddress
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m' 


def clear():
    """
    Clear the terminal from any previous text.
    """
    os.system('cls' if os.name=='nt' else 'clear')


def parse_ip_input(ip_input):
    """
    Parse the IP address input by the user and return a list of IP adresses.

    Supported formats:
    - Single IP adress
    - Comma seperated list of IP adresses
    - CIDR range
    - Dash notation (f.e., 192.168.56.0-13 (from 0 to 13))
    """
    ip_list = []
    if "," in ip_input:
        ip_input = ip_input.replace(" ", "")
        ip_list = ip_input.split(",")
    
    elif "/" in ip_input:
        ip_list = [str(ip) for ip in ipaddress.IPv4Network(ip_input)]
    
    elif "-" in ip_input:
        ip_input_prefix = ".".join(ip_input.split(".")[:3])
        upper_boundary, lower_boundary = ip_input.split(".")[3].split("-")

        for i in range(int(lower_boundary), int(upper_boundary)):
            ip_list.append('{ip_input_prefix}.{i}'.format(ip_input_prefix=ip_input_prefix, i=i))

    else:
        ip_list.append(ip_input)
    
    # Validate the IP addresses
    for ip in ip_list:
        if not validate_ip(ip):
            print('{fail}Invalid IP address: {ip}{endc}'.format(fail=bcolors.FAIL, ip=ip, endc=bcolors.ENDC))
            return []
    
    return ip_list


def validate_ip(ip):
    """
    Validate the IP address input by the user.
    """
    try:
        ipaddress.ip_address(unicode(ip))
        return True
    except ValueError as e:
        print(e)
        return False


def validate_domain(domain):
    """
    Validate the domain input by the user.
    """
    regex = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    if re.search(regex, domain):
        return True
    else:
        return False
