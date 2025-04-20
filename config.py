import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
env_path = Path('.') / '.env'
if env_path.exists():
    with open(env_path, 'r') as f:
        env_contents = f.read()
        
    # Parse .env file manually
    for line in env_contents.splitlines():
        if line and '=' in line:
            key, value = line.split('=', 1)
            os.environ[key] = value

# Network Configuration
NETWORK = "192.168.158.0/24"
GATEWAY_IP = "192.168.158.1"  # Your MacOS gateway IP
INTERFACE = os.environ.get("INTERFACE", "bridge101")  # Default to bridge101

# Attack Configuration
ARP_POISON_INTERVAL = 2  # seconds between ARP poison packets
DHCP_LEASE_TIME = 43200  # 12 hours in seconds
ICMP_REDIRECT_INTERVAL = 5  # seconds between ICMP redirect packets

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FILE = "mitm_attacks.log"

# Database configuration
db_config = {
    'dbname': os.environ.get('DB_NAME', 'mitm_tool'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('DB_PORT', '5432')
}

# Add password only if it's set
password = os.environ.get('DB_PASSWORD')
if password:
    db_config['password'] = password

DB_CONFIG = db_config

# JWT configuration
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-here')
JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour

# Admin code for registration
ADMIN_REGISTRATION_CODE = os.environ.get('ADMIN_REGISTRATION_CODE', 'admin123')

# Security settings
PASSWORD_MIN_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_TIME = 300  # 5 minutes in seconds 