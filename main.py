import argparse
import sys
from utils import setup_logging, print_status, validate_ip
import config
from arp_poison import run_attack as run_arp_poison
from icmp_redirect import run_attack as run_icmp_redirect
from dhcp_spoof import run_attack as run_dhcp_spoof

def setup_argparse():
    parser = argparse.ArgumentParser(description='Man-in-the-Middle Attack Tool')
    subparsers = parser.add_subparsers(dest='attack', help='Attack type')

    # ARP Poisoning
    arp_parser = subparsers.add_parser('arp', help='ARP Poisoning attack')
    arp_parser.add_argument('target_ip', help='Target IP address')
    arp_parser.add_argument('gateway_ip', help='Gateway IP address')

    # ICMP Redirect
    icmp_parser = subparsers.add_parser('icmp', help='ICMP Redirect attack')
    icmp_parser.add_argument('target_ip', help='Target IP address')
    icmp_parser.add_argument('real_gw', help='Real gateway IP address')
    icmp_parser.add_argument('fake_gw', help='Fake gateway IP address')

    # DHCP Spoofing
    dhcp_parser = subparsers.add_parser('dhcp', help='DHCP Spoofing attack')
    dhcp_parser.add_argument('spoofed_ip', help='IP to assign to victims')
    dhcp_parser.add_argument('spoofed_gw', help='Fake gateway IP address')

    return parser

def main():
    # Setup logging
    setup_logging(config.LOG_FILE, config.LOG_LEVEL)

    # Parse arguments
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.attack:
        parser.print_help()
        sys.exit(1)

    # Validate IP addresses
    if args.attack == 'arp':
        if not all(validate_ip(ip) for ip in [args.target_ip, args.gateway_ip]):
            print_status("Invalid IP address format", "error")
            sys.exit(1)
        run_arp_poison(args.target_ip, args.gateway_ip)

    elif args.attack == 'icmp':
        if not all(validate_ip(ip) for ip in [args.target_ip, args.real_gw, args.fake_gw]):
            print_status("Invalid IP address format", "error")
            sys.exit(1)
        run_icmp_redirect(args.target_ip, args.real_gw, args.fake_gw)

    elif args.attack == 'dhcp':
        if not all(validate_ip(ip) for ip in [args.spoofed_ip, args.spoofed_gw]):
            print_status("Invalid IP address format", "error")
            sys.exit(1)
        run_dhcp_spoof(args.spoofed_ip, args.spoofed_gw)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nExiting...", "warning")
        sys.exit(0)
    except Exception as e:
        print_status(f"Error: {e}", "error")
        sys.exit(1) 