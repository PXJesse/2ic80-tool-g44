#encoding = utf-8
import os
import sys
import argparse

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


def main(use_arp, use_dns, use_ssl):
    print(f'2IC80 tool booting up')
    print(f'Selected settings: --arp {use_arp}, --dns {use_dns}, --ssl {use_ssl}')
    
    count_args_true = sum(bool(x) for x in [use_arp, use_dns, use_ssl])
    if count_args_true > 1:
        print(f'{bcolors.WARNING}WARNING: You have selected multiple arguments.{bcolors.ENDC}')


if __name__ == '__main__':
    args = parser.parse_args()

    main(use_arp=args.arp, use_dns=args.dns, use_ssl=args.ssl)

