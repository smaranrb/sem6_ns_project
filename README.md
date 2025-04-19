# Man-in-the-Middle Attack Tool

A Python-based tool for demonstrating various Man-in-the-Middle (MITM) attacks for educational purposes. This tool includes implementations of ARP poisoning and DHCP spoofing attacks.

**WARNING: This tool is for educational purposes only. Do not use it against networks or systems you don't own or have explicit permission to test.**

## Features

- **ARP Poisoning**: Redirect traffic between a target and gateway through the attacker
- **DHCP Spoofing**: Provide fake DHCP responses to assign IP addresses to clients

## Requirements

- Python 3.8+
- Root/Administrator privileges (required for raw socket access)
- Network interface with promiscuous mode support

## Installation

1. Clone the repository:
```bash
git clone https://github.com/smaranrb/sem6_ns_project.git
cd mitm-tool
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

### General Syntax

```bash
sudo python main.py <attack_type> [options]
```

### ARP Poisoning Attack

Redirects traffic between a target and gateway through the attacker.

```bash
sudo python main.py arp <target_ip> <gateway_ip>
```

Example:
```bash
sudo python main.py arp 192.168.1.100 192.168.1.1
```

### DHCP Spoofing Attack

Provides fake DHCP responses to assign IP addresses to clients.

```bash
sudo python main.py dhcp <spoofed_ip> <spoofed_gw> [options]
```

Options:
- `--dns`: DNS servers to assign (default: 8.8.8.8, 8.8.4.4)
- `--lease-time`: DHCP lease time in seconds (default: 43200)
- `--subnet-mask`: Subnet mask to assign (default: 255.255.255.0)
- `--interface`: Network interface to use (default: bridge101)

Example:
```bash
sudo python main.py dhcp 192.168.158.100 192.168.158.1 --dns 1.1.1.1 --subnet-mask 255.255.255.0 --interface bridge101
```

## Verifying DHCP Spoofing Attack

To verify that the DHCP spoofing attack is working:

1. On the victim machine, release the current IP:
```bash
sudo dhclient -r <interface>
```

2. Request a new IP:
```bash
sudo dhclient <interface>
```

3. Check the IP configuration:
```bash
ip addr show <interface>
```

You should see:
- The victim getting an IP in the range you specified
- The gateway set to your spoofed gateway
- The DNS server set to your specified DNS server

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run the tool with sudo/administrator privileges
2. **Interface Not Found**: Make sure to specify the correct network interface
3. **No DHCP Requests**: Ensure the victim's DHCP client is properly configured
4. **Multiple DHCP Servers**: There might be other DHCP servers on the network interfering

### Stopping the Attack

Press `Ctrl+C` to stop the attack. The tool will clean up and exit gracefully.

## Disclaimer

This tool is provided for educational purposes only. Using this tool against networks or systems without explicit permission is illegal and unethical. The authors are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 