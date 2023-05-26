import sys, os, argparse
from util import bcolors

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
            print(f'ARP spoofing selected.\n')
        elif name == 'b':
            print(f'DNS spoofing selected.\n')
        elif name == 'c':
            print(f'SSL stripping selected.\n')
        else:
            print(f'Invalid input. Please try again.\n')

    count_args_true = sum(bool(x) for x in [use_arp, use_dns, use_ssl])

    if count_args_true > 1:
        print(f'{bcolors.WARNING}WARNING: You have selected multiple arguments.{bcolors.ENDC}')


# Entry point: This part runs when the tool is called from the command line using `python tool.py`. The if-statement is not necessary, but good practice.
if __name__ == '__main__':
    args = parser.parse_args()

    main(use_arp=args.arp, use_dns=args.dns, use_ssl=args.ssl)

