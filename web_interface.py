from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
import threading
import time
from main import setup_argparse, run_arp_poison, run_dhcp_spoof
import sys
import os
import logging
from auth import auth_bp, token_required
from models import Database
from config import JWT_SECRET_KEY, INTERFACE
from utils import print_status
from scapy.all import conf

app = Flask(__name__)
app.register_blueprint(auth_bp, url_prefix='/api')
active_attacks = {}
db = Database()
app.secret_key = JWT_SECRET_KEY  # Set secret key for session management

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackThread(threading.Thread):
    def __init__(self, attack_type, args, user_id):
        super().__init__()
        self.attack_type = attack_type
        self.args = args
        self.user_id = user_id
        self.session_id = None
        self._stop_event = threading.Event()
        self.daemon = True
        
        # Ensure the network interface is properly configured
        if hasattr(self.args, 'interface'):
            self.interface = self.args.interface
        else:
            self.interface = INTERFACE
            
        logger.info(f"Attack thread initialized with attack_type={attack_type}, interface={self.interface}")

    def run(self):
        try:
            if self.attack_type == 'arp':
                logger.info(f"Starting ARP poisoning attack: target={self.args.target_ip}, gateway={self.args.gateway_ip}, interface={self.interface}")
                # Explicitly set the interface in scapy's configuration for this thread
                old_iface = conf.iface
                conf.iface = self.interface
                # Pass the interface explicitly to run_arp_poison
                result = run_arp_poison(self.args.target_ip, self.args.gateway_ip, self._stop_event, self.interface)
                # Restore the original interface
                conf.iface = old_iface
                return result
            elif self.attack_type == 'dhcp':
                # Convert DNS string to list if it's not already a list
                if isinstance(self.args.dns, str):
                    dns_servers = self.args.dns.split(',')
                else:
                    dns_servers = self.args.dns
                    
                logger.info(f"Starting DHCP spoofing attack: ip={self.args.spoofed_ip}, gateway={self.args.spoofed_gw}, interface={self.interface}")
                # Explicitly set the interface in scapy's configuration for this thread
                old_iface = conf.iface
                conf.iface = self.interface
                result = run_dhcp_spoof(
                    self.args.spoofed_ip,
                    self.args.spoofed_gw,
                    dns_servers,
                    self.args.lease_time,
                    self.args.subnet_mask,
                    self.interface,
                    self._stop_event
                )
                # Restore the original interface
                conf.iface = old_iface
                return result
        except Exception as e:
            logger.error(f"Error in attack thread: {str(e)}")
            db.log_action(self.user_id, f"{self.attack_type}_error", f"Error in {self.attack_type} attack: {str(e)}")
            return False

    def stop(self):
        logger.info(f"Stopping {self.attack_type} attack")
        # Give the thread time to properly clean up
        self._stop_event.set()
        # Wait for a moment to allow cleanup
        time.sleep(1)

@app.route('/')
def index():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/api/start_attack', methods=['POST'])
@token_required
def start_attack(current_user):
    data = request.json
    attack_type = data.get('attack_type')
    
    logger.info(f"User {current_user['username']} requested to start {attack_type} attack")
    
    # Check user permissions
    permissions = db.get_user_permissions(current_user['id'])
    attack_permission = next((p for p in permissions if p['attack_type'] == attack_type), None)
    
    if not attack_permission or not attack_permission['can_start']:
        logger.warning(f"Permission denied for user {current_user['username']} to start {attack_type} attack")
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403
    
    if attack_type in active_attacks:
        logger.warning(f"{attack_type} attack is already running")
        return jsonify({'status': 'error', 'message': f'{attack_type} attack is already running'})
    
    # Create argument parser and parse arguments
    parser = setup_argparse()
    
    try:
        if attack_type == 'arp':
            # Ensure both target_ip and gateway_ip are provided and not empty
            if not data.get('target_ip') or not data.get('gateway_ip'):
                logger.error("Missing target_ip or gateway_ip for ARP poisoning attack")
                return jsonify({'status': 'error', 'message': 'Missing target_ip or gateway_ip'}), 400
                
            # Use parse_args with all required arguments
            args = parser.parse_args(['arp', data['target_ip'], data['gateway_ip']])
            
            # Set the interface if provided
            if 'interface' in data and data['interface']:
                setattr(args, 'interface', data['interface'])
            logger.info(f"ARP attack parameters: target_ip={data['target_ip']}, gateway_ip={data['gateway_ip']}, interface={getattr(args, 'interface', INTERFACE)}")
                
        elif attack_type == 'dhcp':
            # Ensure required parameters are provided
            if not data.get('spoofed_ip') or not data.get('spoofed_gw'):
                logger.error("Missing spoofed_ip or spoofed_gw for DHCP spoofing attack")
                return jsonify({'status': 'error', 'message': 'Missing spoofed_ip or spoofed_gw'}), 400
                
            args = parser.parse_args([
                'dhcp',
                data['spoofed_ip'],
                data['spoofed_gw'],
                '--dns', data.get('dns', '8.8.8.8,8.8.4.4'),
                '--lease-time', str(data.get('lease_time', 43200)),
                '--subnet-mask', data.get('subnet_mask', '255.255.255.0'),
                '--interface', data.get('interface', 'bridge101')
            ])
            logger.info(f"DHCP attack parameters: spoofed_ip={data['spoofed_ip']}, spoofed_gw={data['spoofed_gw']}, interface={args.interface}")
        else:
            logger.warning(f"Invalid attack type: {attack_type}")
            return jsonify({'status': 'error', 'message': 'Invalid attack type'}), 400
        
        # Create attack session in database
        session_id = db.create_attack_session(current_user['id'], attack_type, data)
        
        # Start attack in a separate thread
        attack_thread = AttackThread(attack_type, args, current_user['id'])
        attack_thread.session_id = session_id
        active_attacks[attack_type] = attack_thread
        attack_thread.start()
        
        # Log the action
        db.log_action(current_user['id'], 'start_attack', f'Started {attack_type} attack')
        
        logger.info(f"Successfully started {attack_type} attack for user {current_user['username']}")
        return jsonify({'status': 'success', 'message': f'Started {attack_type} attack'})
    except Exception as e:
        logger.error(f"Error starting {attack_type} attack: {str(e)}")
        db.log_action(current_user['id'], 'start_attack_error', f'Error starting {attack_type} attack: {str(e)}')
        return jsonify({'status': 'error', 'message': f'Error starting attack: {str(e)}'}), 500

@app.route('/api/stop_attack', methods=['POST'])
@token_required
def stop_attack(current_user):
    data = request.json
    attack_type = data.get('attack_type')
    
    logger.info(f"User {current_user['username']} requested to stop {attack_type} attack")
    
    # Check user permissions
    permissions = db.get_user_permissions(current_user['id'])
    attack_permission = next((p for p in permissions if p['attack_type'] == attack_type), None)
    
    if not attack_permission or not attack_permission['can_stop']:
        logger.warning(f"Permission denied for user {current_user['username']} to stop {attack_type} attack")
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403
    
    if attack_type not in active_attacks:
        logger.warning(f"No {attack_type} attack is running")
        return jsonify({'status': 'error', 'message': f'No {attack_type} attack is running'})
    
    try:
        # Stop the attack thread
        attack_thread = active_attacks[attack_type]
        attack_thread.stop()
        
        # Update attack session in database if session_id exists
        if attack_thread.session_id:
            db.update_attack_session(attack_thread.session_id, 'stopped')
        
        # Log the action
        db.log_action(current_user['id'], 'stop_attack', f'Stopped {attack_type} attack')
        
        del active_attacks[attack_type]
        
        logger.info(f"Successfully stopped {attack_type} attack for user {current_user['username']}")
        return jsonify({'status': 'success', 'message': f'Stopped {attack_type} attack'})
    except Exception as e:
        logger.error(f"Error stopping {attack_type} attack: {str(e)}")
        db.log_action(current_user['id'], 'stop_attack_error', f'Error stopping {attack_type} attack: {str(e)}')
        return jsonify({'status': 'error', 'message': f'Error stopping attack: {str(e)}'}), 500

@app.route('/api/status', methods=['GET'])
@token_required
def get_status(current_user):
    status = {
        'arp': 'running' if 'arp' in active_attacks else 'stopped',
        'dhcp': 'running' if 'dhcp' in active_attacks else 'stopped'
    }
    return jsonify(status)

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    app.run(host='0.0.0.0', port=5000) 