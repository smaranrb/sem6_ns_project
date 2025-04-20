from flask import Flask, render_template, redirect, url_for, request, jsonify, send_from_directory
from models import Database
from auth import auth_bp, token_required, get_jwt_identity
import jwt
import os
import subprocess
import json
from config import JWT_SECRET_KEY, ADMIN_CODE
from datetime import datetime
import signal
import threading
import time
from threading import Thread

app = Flask(__name__)
app.register_blueprint(auth_bp, url_prefix='/api')

# Initialize database
db = Database()

# Store active attack processes
active_attacks = {}
attack_lock = threading.Lock()

# Store running attack processes
attack_processes = {}

# Web Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

# API Routes
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def dashboard_stats(current_user):
    with attack_lock:
        active_count = len(active_attacks)
    
    # Get total attacks from database
    total_attacks = db.execute_query(
        "SELECT COUNT(*) as count FROM attack_sessions",
        fetch_one=True
    )
    
    # Get total users from database
    total_users = db.execute_query(
        "SELECT COUNT(*) as count FROM users",
        fetch_one=True
    )
    
    return jsonify({
        'active_attacks': active_count,
        'total_attacks': total_attacks['count'] if total_attacks else 0,
        'total_users': total_users['count'] if total_users else 0
    })

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    # Get user permissions
    permissions = db.get_user_permissions(current_user['id'])
    
    # Get user activity
    activity = db.execute_query(
        "SELECT * FROM system_logs WHERE user_id = %s ORDER BY timestamp DESC LIMIT 10",
        (current_user['id'],)
    )
    
    # Get user attack sessions
    sessions = db.execute_query(
        "SELECT * FROM attack_sessions WHERE user_id = %s ORDER BY created_at DESC LIMIT 10",
        (current_user['id'],)
    )
    
    return jsonify({
        'username': current_user['username'],
        'email': current_user['email'],
        'role': current_user['role'],
        'created_at': current_user['created_at'].isoformat() if isinstance(current_user['created_at'], datetime) else current_user['created_at'],
        'permissions': permissions,
        'activity': activity,
        'sessions': sessions
    })

@app.route('/api/profile/update', methods=['POST'])
@token_required
def update_profile(current_user):
    data = request.get_json()
    
    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400
    
    # Update user email
    try:
        db.execute_query(
            "UPDATE users SET email = %s WHERE id = %s",
            (data['email'], current_user['id']),
            commit=True
        )
        
        # Log action
        db.log_action(current_user['id'], 'profile_update', f"Updated email to {data['email']}")
        
        return jsonify({'message': 'Profile updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile/change-password', methods=['POST'])
@token_required
def change_password(current_user):
    data = request.get_json()
    
    if not data or 'current_password' not in data or 'new_password' not in data:
        return jsonify({'error': 'Current password and new password are required'}), 400
    
    # Verify current password
    user = db.verify_user(current_user['username'], data['current_password'])
    if not user:
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Update password
    try:
        import bcrypt
        from config import SECURITY_CONFIG
        
        if len(data['new_password']) < SECURITY_CONFIG['password_min_length']:
            return jsonify({'error': f"Password must be at least {SECURITY_CONFIG['password_min_length']} characters long"}), 400
        
        # Hash new password
        password_hash = bcrypt.hashpw(data['new_password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update user password
        db.execute_query(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (password_hash, current_user['id']),
            commit=True
        )
        
        # Log action
        db.log_action(current_user['id'], 'password_change', "Password changed")
        
        return jsonify({'message': 'Password changed successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attacks', methods=['GET'])
@token_required
def get_attacks(current_user):
    # Get user's attack sessions
    if current_user['role'] == 'admin':
        # Admins can see all attacks
        sessions = db.execute_query(
            """
            SELECT a.*, u.username 
            FROM attack_sessions a 
            JOIN users u ON a.user_id = u.id 
            ORDER BY a.created_at DESC
            """
        )
    else:
        # Regular users can only see their own attacks
        sessions = db.execute_query(
            "SELECT * FROM attack_sessions WHERE user_id = %s ORDER BY created_at DESC",
            (current_user['id'],)
        )
    
    # Mark active attacks
    with attack_lock:
        for session in sessions:
            session['is_active'] = str(session['id']) in active_attacks
    
    return jsonify(sessions)

@app.route('/api/attacks/start', methods=['POST'])
@token_required
def start_attack(current_user):
    data = request.get_json()
    
    if not data or 'attack_type' not in data:
        return jsonify({'error': 'Attack type is required'}), 400
    
    attack_type = data['attack_type']
    
    # Check if user has permission for this attack type
    permissions = db.get_user_permissions(current_user['id'])
    if attack_type not in permissions and current_user['role'] != 'admin':
        return jsonify({'error': f'You do not have permission to perform {attack_type} attacks'}), 403
    
    # Create attack session record
    session_id = db.create_attack_session(
        user_id=current_user['id'],
        attack_type=attack_type,
        parameters=json.dumps(data)
    )
    
    if not session_id:
        return jsonify({'error': 'Failed to create attack session'}), 500
    
    # Prepare command based on attack type
    command = ['python', 'main.py']
    
    if attack_type == 'arp':
        if 'target_ip' not in data or 'gateway_ip' not in data:
            return jsonify({'error': 'Target IP and Gateway IP are required for ARP poisoning'}), 400
        
        command.extend(['arp', data['target_ip'], data['gateway_ip']])
        
        if 'interface' in data and data['interface']:
            command.extend(['--interface', data['interface']])
    
    elif attack_type == 'dhcp':
        if 'spoofed_ip' not in data or 'spoofed_gw' not in data:
            return jsonify({'error': 'Spoofed IP and Gateway are required for DHCP spoofing'}), 400
        
        command.extend(['dhcp', data['spoofed_ip'], data['spoofed_gw']])
        
        if 'dns' in data and data['dns']:
            command.extend(['--dns', data['dns']])
        
        if 'subnet_mask' in data and data['subnet_mask']:
            command.extend(['--subnet-mask', data['subnet_mask']])
        
        if 'lease_time' in data and data['lease_time']:
            command.extend(['--lease-time', str(data['lease_time'])])
        
        if 'interface' in data and data['interface']:
            command.extend(['--interface', data['interface']])
    
    else:
        # Log error and update session
        db.update_attack_session(session_id, 'failed', f"Unsupported attack type: {attack_type}")
        return jsonify({'error': f'Unsupported attack type: {attack_type}'}), 400
    
    try:
        # Start attack process
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid  # To allow process group termination
        )
        
        # Store process reference with session ID as key
        with attack_lock:
            active_attacks[str(session_id)] = {
                'process': process,
                'command': ' '.join(command),
                'start_time': datetime.now(),
                'user_id': current_user['id']
            }
        
        # Log action
        db.log_action(
            current_user['id'], 
            f'{attack_type}_attack_started',
            f"Started {attack_type} attack (Session ID: {session_id})"
        )
        
        # Update session status
        db.update_attack_session(session_id, 'active', 'Attack started successfully')
        
        # Start a thread to monitor the process
        threading.Thread(
            target=monitor_attack_process, 
            args=(session_id, process),
            daemon=True
        ).start()
        
        return jsonify({
            'message': f'{attack_type.upper()} attack started successfully',
            'session_id': session_id
        })
    
    except Exception as e:
        error_msg = str(e)
        # Update session status
        db.update_attack_session(session_id, 'failed', error_msg)
        return jsonify({'error': f'Failed to start attack: {error_msg}'}), 500

@app.route('/api/attacks/<int:attack_id>/stop', methods=['POST'])
@token_required
def stop_attack(current_user, attack_id):
    # Check if attack exists
    attack_session = db.execute_query(
        "SELECT * FROM attack_sessions WHERE id = %s",
        (attack_id,),
        fetch_one=True
    )
    
    if not attack_session:
        return jsonify({'error': 'Attack session not found'}), 404
    
    # Check if user is authorized to stop this attack
    if attack_session['user_id'] != current_user['id'] and current_user['role'] != 'admin':
        return jsonify({'error': 'You are not authorized to stop this attack'}), 403
    
    # Check if attack is active
    with attack_lock:
        if str(attack_id) not in active_attacks:
            return jsonify({'error': 'Attack is not active or already stopped'}), 400
        
        try:
            # Get process group ID
            process = active_attacks[str(attack_id)]['process']
            pgid = os.getpgid(process.pid)
            
            # Terminate process group
            os.killpg(pgid, signal.SIGTERM)
            
            # Remove from active attacks
            del active_attacks[str(attack_id)]
            
            # Update session status
            db.update_attack_session(attack_id, 'stopped', 'Attack stopped by user')
            
            # Log action
            db.log_action(
                current_user['id'], 
                'attack_stopped',
                f"Stopped attack (Session ID: {attack_id})"
            )
            
            return jsonify({'message': 'Attack stopped successfully'})
        
        except Exception as e:
            return jsonify({'error': f'Failed to stop attack: {str(e)}'}), 500

def monitor_attack_process(session_id, process):
    """Monitor a running attack process and update its status when completed"""
    # Wait for process to complete or be terminated
    stdout, stderr = process.communicate()
    
    # Get exit code
    exit_code = process.returncode
    
    # Update session status based on exit code
    status = 'completed' if exit_code == 0 else 'failed'
    details = f"Exit code: {exit_code}"
    
    if stderr:
        details += f"\nErrors: {stderr.decode('utf-8')}"
    
    # Update database
    db.update_attack_session(session_id, status, details)
    
    # Remove from active attacks
    with attack_lock:
        if str(session_id) in active_attacks:
            del active_attacks[str(session_id)]

# API Routes for attacks
@app.route('/api/attacks/arp', methods=['POST'])
@token_required
def launch_arp_attack(current_user):
    user_id = current_user['id']
    
    # Check permissions
    permissions = db.get_user_permissions(user_id)
    if not permissions.get('arp_poisoning', False):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    # Get attack parameters
    data = request.json
    target_ip = data.get('target_ip')
    gateway_ip = data.get('gateway_ip')
    interface = data.get('interface', 'bridge101')
    
    if not target_ip or not gateway_ip:
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400
    
    # Log the attack session
    session_id = db.create_attack_session(
        user_id=user_id,
        attack_type='arp_poisoning',
        parameters=json.dumps({
            'target_ip': target_ip,
            'gateway_ip': gateway_ip,
            'interface': interface
        }),
        affected_clients=json.dumps([target_ip])
    )
    
    # Build command
    cmd = ['python', 'main.py', 'arp', target_ip, gateway_ip, '--interface', interface]
    
    # Launch attack process
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        attack_processes[session_id] = {
            'process': process,
            'type': 'arp_poisoning',
            'started_at': time.time(),
            'targets': target_ip,
            'user_id': user_id
        }
        
        # Log action
        db.log_action(user_id, f"Launched ARP poisoning attack targeting {target_ip}")
        
        # Start a monitoring thread
        Thread(target=monitor_attack_process, args=(session_id, process)).start()
        
        return jsonify({
            'success': True, 
            'message': 'ARP poisoning attack launched successfully',
            'session_id': session_id
        })
    except Exception as e:
        db.log_action(user_id, f"Failed to launch ARP poisoning attack: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/attacks/dhcp', methods=['POST'])
@token_required
def launch_dhcp_attack(current_user):
    user_id = current_user['id']
    
    # Check permissions
    permissions = db.get_user_permissions(user_id)
    if not permissions.get('dhcp_spoofing', False):
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    # Get attack parameters
    data = request.json
    spoofed_ip = data.get('spoofed_ip')
    spoofed_gw = data.get('spoofed_gw')
    dns = data.get('dns', '1.1.1.1')
    subnet_mask = data.get('subnet_mask', '255.255.255.0')
    interface = data.get('interface', 'bridge101')
    
    if not spoofed_ip or not spoofed_gw:
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400
    
    # Log the attack session
    session_id = db.create_attack_session(
        user_id=user_id,
        attack_type='dhcp_spoofing',
        parameters=json.dumps({
            'spoofed_ip': spoofed_ip,
            'spoofed_gw': spoofed_gw,
            'dns': dns,
            'subnet_mask': subnet_mask,
            'interface': interface
        }),
        affected_clients=json.dumps(["TBD - captured during attack"])
    )
    
    # Build command
    cmd = ['python', 'main.py', 'dhcp', spoofed_ip, spoofed_gw, 
           '--dns', dns, '--subnet-mask', subnet_mask, '--interface', interface]
    
    # Launch attack process
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        attack_processes[session_id] = {
            'process': process,
            'type': 'dhcp_spoofing',
            'started_at': time.time(),
            'targets': "DHCP clients",
            'user_id': user_id
        }
        
        # Log action
        db.log_action(user_id, f"Launched DHCP spoofing attack offering IP {spoofed_ip}")
        
        # Start a monitoring thread
        Thread(target=monitor_attack_process, args=(session_id, process)).start()
        
        return jsonify({
            'success': True, 
            'message': 'DHCP spoofing attack launched successfully',
            'session_id': session_id
        })
    except Exception as e:
        db.log_action(user_id, f"Failed to launch DHCP spoofing attack: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/attacks/active', methods=['GET'])
@token_required
def get_active_attacks(current_user):
    user_id = current_user['id']
    is_admin = current_user['role'] == 'admin'
    
    # Prepare active attacks list
    active_attacks = []
    
    for attack_id, attack_info in attack_processes.items():
        # For admins, show all attacks, for others, show only their own
        if is_admin or attack_info['user_id'] == user_id:
            active_attacks.append({
                'id': attack_id,
                'type': attack_info['type'],
                'started_at': attack_info['started_at'],
                'targets': attack_info['targets']
            })
    
    return jsonify({'attacks': active_attacks})

@app.route('/api/attacks/<int:attack_id>/stop', methods=['POST'])
@token_required
def stop_attack_in_processes(current_user, attack_id):
    user_id = current_user['id']
    is_admin = current_user['role'] == 'admin'
    
    if attack_id not in attack_processes:
        return jsonify({'success': False, 'message': 'Attack not found'}), 404
    
    attack_info = attack_processes[attack_id]
    
    # Only allow users to stop their own attacks unless they are admin
    if not is_admin and attack_info['user_id'] != user_id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403
    
    try:
        # Terminate the process
        if attack_info['process'].poll() is None:  # Process is still running
            attack_info['process'].terminate()
            attack_info['process'].wait(timeout=5)
            
            # Force kill if still running
            if attack_info['process'].poll() is None:
                attack_info['process'].kill()
        
        # Update attack session in database
        db.update_attack_session(attack_id, status="stopped")
        
        # Log the action
        db.log_action(user_id, f"Stopped {attack_info['type']} attack (ID: {attack_id})")
        
        # Remove from active attacks
        del attack_processes[attack_id]
        
        return jsonify({'success': True, 'message': 'Attack stopped successfully'})
    except Exception as e:
        db.log_action(user_id, f"Failed to stop attack: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

def monitor_attack_process(session_id, process):
    """Monitor a running attack process and update status when it ends"""
    process.wait()
    
    # If process ended naturally, update the database
    if session_id in attack_processes:
        db.update_attack_session(session_id, status="completed")
        del attack_processes[session_id]

# New route for viewing activity logs
@app.route('/api/activity-logs', methods=['GET'])
@token_required
def get_activity_logs(current_user):
    user_id = current_user['id']
    is_admin = current_user['role'] == 'admin'
    
    try:
        # If user is admin, get all logs, otherwise get only user's logs
        if is_admin:
            logs = db.execute_query(
                """
                SELECT l.*, u.username 
                FROM system_logs l 
                JOIN users u ON l.user_id = u.id 
                ORDER BY l.timestamp DESC 
                LIMIT 100
                """
            )
        else:
            logs = db.execute_query(
                """
                SELECT l.*, u.username 
                FROM system_logs l 
                JOIN users u ON l.user_id = u.id 
                WHERE l.user_id = %s 
                ORDER BY l.timestamp DESC 
                LIMIT 100
                """,
                (user_id,)
            )
        
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# New route for viewing attack sessions
@app.route('/api/attack-sessions', methods=['GET'])
@token_required
def get_attack_sessions(current_user):
    user_id = current_user['id']
    is_admin = current_user['role'] == 'admin'
    
    try:
        # If user is admin, get all sessions, otherwise get only user's sessions
        if is_admin:
            sessions = db.execute_query(
                """
                SELECT s.*, u.username 
                FROM attack_sessions s 
                JOIN users u ON s.user_id = u.id 
                ORDER BY s.started_at DESC 
                LIMIT 100
                """
            )
        else:
            sessions = db.execute_query(
                """
                SELECT s.*, u.username 
                FROM attack_sessions s 
                JOIN users u ON s.user_id = u.id 
                WHERE s.user_id = %s 
                ORDER BY s.started_at DESC 
                LIMIT 100
                """,
                (user_id,)
            )
        
        return jsonify({'success': True, 'sessions': sessions})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Admin endpoints
@app.route('/admin/users')
def admin_users():
    return render_template('admin_users.html')

@app.route('/api/admin/users', methods=['GET'])
@token_required
def get_users(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Admin access required'}), 403
    
    # Get all users from database
    users = db.get_all_users()
    return jsonify({'users': users})

# Create all required database tables on startup
with app.app_context():
    db.create_tables()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 