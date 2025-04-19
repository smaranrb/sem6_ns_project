from flask import Flask, render_template, request, jsonify
import threading
import time
from main import setup_argparse, run_arp_poison, run_dhcp_spoof
import sys
import os

app = Flask(__name__)
active_attacks = {}

class AttackThread(threading.Thread):
    def __init__(self, attack_type, args):
        super().__init__()
        self.attack_type = attack_type
        self.args = args
        self._stop_event = threading.Event()
        self.daemon = True

    def run(self):
        if self.attack_type == 'arp':
            run_arp_poison(self.args.target_ip, self.args.gateway_ip, self._stop_event)
        elif self.attack_type == 'dhcp':
            # Convert DNS string to list
            dns_servers = self.args.dns.split(',')
            run_dhcp_spoof(
                self.args.spoofed_ip,
                self.args.spoofed_gw,
                dns_servers,
                self.args.lease_time,
                self.args.subnet_mask,
                self.args.interface,
                self._stop_event
            )

    def stop(self):
        self._stop_event.set()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start_attack', methods=['POST'])
def start_attack():
    data = request.json
    attack_type = data.get('attack_type')
    
    if attack_type in active_attacks:
        return jsonify({'status': 'error', 'message': f'{attack_type} attack is already running'})
    
    # Create argument parser and parse arguments
    parser = setup_argparse()
    
    if attack_type == 'arp':
        args = parser.parse_args(['arp', data['target_ip'], data['gateway_ip']])
    elif attack_type == 'dhcp':
        args = parser.parse_args([
            'dhcp',
            data['spoofed_ip'],
            data['spoofed_gw'],
            '--dns', data.get('dns', '8.8.8.8,8.8.4.4'),
            '--lease-time', str(data.get('lease_time', 43200)),
            '--subnet-mask', data.get('subnet_mask', '255.255.255.0'),
            '--interface', data.get('interface', 'bridge101')
        ])
    else:
        return jsonify({'status': 'error', 'message': 'Invalid attack type'})
    
    # Start attack in a separate thread
    attack_thread = AttackThread(attack_type, args)
    active_attacks[attack_type] = attack_thread
    attack_thread.start()
    
    return jsonify({'status': 'success', 'message': f'Started {attack_type} attack'})

@app.route('/api/stop_attack', methods=['POST'])
def stop_attack():
    data = request.json
    attack_type = data.get('attack_type')
    
    if attack_type not in active_attacks:
        return jsonify({'status': 'error', 'message': f'No {attack_type} attack is running'})
    
    # Stop the attack thread
    active_attacks[attack_type].stop()
    del active_attacks[attack_type]
    
    return jsonify({'status': 'success', 'message': f'Stopped {attack_type} attack'})

@app.route('/api/status', methods=['GET'])
def get_status():
    status = {
        'arp': 'running' if 'arp' in active_attacks else 'stopped',
        'dhcp': 'running' if 'dhcp' in active_attacks else 'stopped'
    }
    return jsonify(status)

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    app.run(host='0.0.0.0', port=5000) 