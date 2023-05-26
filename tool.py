import sys, os, argparse 
from util import bcolors
import scapy
from scapy.all import *

# Set up argument parser for using arguments in the command line
parser = argparse.ArgumentParser(
    prog='2IC80 tool',
    description='A tool for ARP/DNS spoofing with SSL stripping capabilities',
    epilog='Good luck!'
)

parser.add_argument(
    '--arp',
    action='store_true',
    help='Run the ARP spoofer'
)

parser.add_argument(
    '--dns',
    action='store_true',
    help='Run the DNS spoofer'
)

parser.add_argument(
    '--ssl',
    action='store_true',
    help='Run SSL stripping'
)


def ARPposioning():
    macAttacker= input("Enter MAC address of attacker: ")  
    ipAttacker= input("Enter IP address of attacker: ")

    victimNumber=input('Do you want to spoof one or multiple victims? (1/m)')
    if victimNumber == "1":
        macVictim= input("Enter MAC address of victim: ")
        ipVictim= input("Enter IP address of victim: ")

        ipToSpoof= input("Enter IP address to spoof: ")
        print(ipVictim)
        # arp=Ether() / ARP()
        # arp[Ether].src= macAttacker
        # arp[ARP].hwsrc= macAttacker
        # arp[ARP].psrc= ipToSpoof
        # arp[ARP].hwdst= macVictim
        # arp[ARP].pdst= ipVictim
        print("\n\n")
    
    elif victimNumber == "m":   
        IPrange=input('What is the range of IP addresses?')
        IpToSpoof=input('What is the IP address to spoof?')
        if "-" in IPrange:
            upperBoundary=IPrange.split("-")[1]
            lowerBoundary=lowerBoundary=IPrange.split(".")[3].split("-")[0]

            for i in range(int(lowerBoundary), int(upperBoundary)):
                macVictim= "To be determined"
                ipVictim= IPrange.split(".")[0]+"."+IPrange.split(".")[1]+"."+IPrange.split(".")[2]+"."+str(i)

                print(ipVictim)
                # arp=Ether() / ARP()
                # arp[Ether].src= macAttacker
                # arp[ARP].hwsrc= macAttacker
                # arp[ARP].psrc= ipToSpoof
                # arp[ARP].hwdst= macVictim
                # arp[ARP].pdst= ipVictim
        else:
            print("Invalid input. Please try again.")

        print("\n\n")
    

    # sendp(arp, iface="ënp0s3")

def DNSposioning():
    print(f'DNS spoofing selected.\n')

def SSLstripping():
    print(f'SSL stripping selected.\n')


def main(use_arp, use_dns, use_ssl):
    print(f'2IC80 tool booting up')
    # print(f'Selected settings: --arp {use_arp}, --dns {use_dns}, --ssl {use_ssl} \n')
    while True:
        print(f'Select the preferred attack from the list below:\n')
        print(f'    a) ARP spoofing')
        print(f'    b) DNS spoofing')
        print(f'    c) SSL stripping')
        print(f'    d) Exit\n')
        name=input(f'\nYour choice: ')
        print(f'\n')
        print(f'You have selected {name}.\n')

        if name == 'd':
            break
        elif name == 'a':
            ARPposioning()
        elif name == 'b':
            DNSposioning()
        elif name == 'c':
            SSLstripping()
        else:
            print(f'Invalid input. Please try again.\n')

    count_args_true = sum(bool(x) for x in [use_arp, use_dns, use_ssl])

    if count_args_true > 1:
        print(f'{bcolors.WARNING}WARNING: You have selected multiple arguments.{bcolors.ENDC}')



# Entry point: This part runs when the tool is called from the command line using `python tool.py`. The if-statement is not necessary, but good practice.
if __name__ == '__main__':
    args = parser.parse_args()

    main(use_arp=args.arp, use_dns=args.dns, use_ssl=args.ssl)

