# Man-in-the-Middle Attack Tool

This tool implements various man-in-the-middle attacks for educational purposes. It includes implementations of:
- ARP Poisoning
- ICMP Redirect
- DHCP Spoofing

## Prerequisites

- Python 3.7+
- Root/Administrator privileges (required for packet manipulation)
- Scapy and other Python dependencies

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd mitm-tool
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Network Setup

1. Ensure your VMs are on the same network (192.168.158.0/24)
2. Configure your MacOS host as the gateway (192.168.158.1)
3. Enable IP forwarding on your MacOS:
```bash
sudo sysctl -w net.inet.ip.forwarding=1
```

## Usage

### ARP Poisoning
```bash
sudo python main.py arp <target_ip> <gateway_ip>
```
Example:
```bash
sudo python main.py arp 192.168.158.2 192.168.158.1
```

### ICMP Redirect
```bash
sudo python main.py icmp <target_ip> <real_gateway> <fake_gateway>
```
Example:
```bash
sudo python main.py icmp 192.168.158.2 192.168.158.1 192.168.158.3
```

### DHCP Spoofing
```bash
sudo python main.py dhcp <spoofed_ip> <spoofed_gateway>
```
Example:
```bash
sudo python main.py dhcp 192.168.158.100 192.168.158.3
```

## Important Notes

1. Always run with sudo/administrator privileges
2. Use responsibly and only in controlled environments
3. Some attacks may require additional system configuration
4. Modern operating systems may have protections against these attacks

## Troubleshooting

1. If attacks don't work:
   - Check network connectivity
   - Verify IP forwarding is enabled
   - Ensure correct network interface is being used
   - Check firewall settings

2. Common issues:
   - "Operation not permitted" - Run with sudo
   - "No such device" - Check interface name in config.py
   - "Address already in use" - Stop other DHCP servers

## License

This tool is for educational purposes only. Use responsibly and ethically. 