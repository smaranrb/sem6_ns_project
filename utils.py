import logging
import netifaces
import platform
import subprocess
from scapy.all import get_if_addr, get_if_hwaddr
from colorama import Fore, Style, init
import sys

# Initialize colorama
init()

def setup_logging(log_file, log_level):
    """Configure logging with both file and console handlers."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def get_interface_info(interface):
    """Get IP and MAC address for the specified interface."""
    try:
        ip = get_if_addr(interface)
        mac = get_if_hwaddr(interface)
        return ip, mac
    except Exception as e:
        logging.error(f"Failed to get interface info: {e}")
        return None, None

def enable_ip_forwarding():
    """Enable IP forwarding on the system."""
    try:
        system = platform.system().lower()
        
        if system == 'darwin':  # macOS
            # Check if forwarding is already enabled
            result = subprocess.run(['sysctl', 'net.inet.ip.forwarding'], 
                                   capture_output=True, text=True)
            current_value = result.stdout.strip().split(': ')[1]
            
            if current_value == '0':
                # Enable forwarding
                subprocess.run(['sudo', 'sysctl', '-w', 'net.inet.ip.forwarding=1'], 
                              check=True)
                return True
            return True  # Already enabled
            
        elif system == 'linux':
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            return True
            
        else:
            logging.error(f"Unsupported operating system: {system}")
            return False
            
    except Exception as e:
        logging.error(f"Failed to enable IP forwarding: {e}")
        return False

def print_status(message, status="info"):
    """Print colored status messages."""
    colors = {
        "info": Fore.BLUE,
        "success": Fore.GREEN,
        "error": Fore.RED,
        "warning": Fore.YELLOW
    }
    color = colors.get(status, Fore.WHITE)
    print(f"{color}[{status.upper()}] {message}{Style.RESET_ALL}")

def validate_ip(ip):
    """Validate IP address format."""
    if not ip:
        return False
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except (AttributeError, TypeError, ValueError):
        return False

def validate_ip_with_error(ip, ip_name=""):
    """Validate IP address and print error if invalid."""
    if not validate_ip(ip):
        error_msg = f"Invalid {ip_name + ' ' if ip_name else ''}IP address: {ip}"
        print_status(error_msg, "error")
        return False
    return True 