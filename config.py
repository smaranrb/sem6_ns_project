import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Network Configuration
NETWORK = "192.168.158.0/24"
GATEWAY_IP = "192.168.158.1"  # Your MacOS gateway IP
INTERFACE = os.getenv("INTERFACE", "bridge101")  # Default to bridge101

# Attack Configuration
ARP_POISON_INTERVAL = 2  # seconds between ARP poison packets
DHCP_LEASE_TIME = 43200  # 12 hours in seconds
ICMP_REDIRECT_INTERVAL = 5  # seconds between ICMP redirect packets

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FILE = "mitm_attacks.log" 