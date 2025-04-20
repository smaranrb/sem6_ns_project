from flask import Blueprint, request, jsonify, session
from functools import wraps
import jwt
from datetime import datetime, timedelta
from models import Database
from config import JWT_SECRET_KEY, ADMIN_REGISTRATION_CODE

auth_bp = Blueprint('auth', __name__)
db = Database()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            # Try to get from cookies
            token = request.cookies.get('token')
            if not token:
                return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            db.cur.execute("""
                SELECT id, username, role, is_active
                FROM users
                WHERE id = %s
            """, (data['user_id'],))
            current_user = db.cur.fetchone()
            
            if not current_user or not current_user['is_active']:
                return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'message': f'Token is invalid: {str(e)}'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    admin_code = data.get('admin_code')

    if not all([username, password, email]):
        return jsonify({'message': 'Missing required fields'}), 400

    # Determine role based on admin code
    role = 'admin' if admin_code == ADMIN_REGISTRATION_CODE else 'user'

    try:
        user_id = db.create_user(username, password, email, role)
        
        # Set default permissions based on role
        permissions = []
        if role == 'admin':
            permissions = [
                {'attack_type': 'arp', 'can_start': True, 'can_stop': True, 'can_view_logs': True},
                {'attack_type': 'dhcp', 'can_start': True, 'can_stop': True, 'can_view_logs': True}
            ]
        elif role == 'user':
            permissions = [
                {'attack_type': 'arp', 'can_start': True, 'can_stop': True, 'can_view_logs': False},
                {'attack_type': 'dhcp', 'can_start': True, 'can_stop': True, 'can_view_logs': False}
            ]
        else:  # guest
            permissions = [
                {'attack_type': 'arp', 'can_start': False, 'can_stop': False, 'can_view_logs': False},
                {'attack_type': 'dhcp', 'can_start': False, 'can_stop': False, 'can_view_logs': False}
            ]
        
        db.set_user_permissions(user_id, permissions)
        db.log_action(user_id, 'register', f'User {username} registered as {role}')
        
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 400

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'message': 'Missing username or password'}), 400

    user = db.verify_user(username, password)
    if not user:
        return jsonify({'message': 'Invalid credentials or account locked'}), 401

    # Generate JWT token
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.utcnow() + timedelta(seconds=3600)
    }, JWT_SECRET_KEY, algorithm='HS256')

    db.log_action(user['id'], 'login', 'User logged in successfully')
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    })

@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    db.log_action(current_user['id'], 'logout', 'User logged out')
    return jsonify({'message': 'Logged out successfully'})

@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    permissions = db.get_user_permissions(current_user['id'])
    sessions = db.get_user_sessions(current_user['id'])
    
    return jsonify({
        'user': {
            'id': current_user['id'],
            'username': current_user['username'],
            'role': current_user['role']
        },
        'permissions': permissions,
        'sessions': sessions
    })

@auth_bp.route('/api/activity-logs', methods=['GET'])
@token_required
def get_activity_logs(current_user):
    try:
        logs = db.get_user_logs(current_user['id'])
        return jsonify({
            'status': 'success',
            'logs': logs
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@auth_bp.route('/api/attack-sessions', methods=['GET'])
@token_required
def get_attack_sessions(current_user):
    try:
        sessions = db.get_user_sessions(current_user['id'])
        return jsonify({
            'status': 'success',
            'sessions': sessions
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@auth_bp.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        users = db.get_all_users()
        for user in users:
            # Get permissions for each user
            permissions = db.get_user_permissions(user['id'])
            user['permissions'] = {}
            for perm in permissions:
                if perm['attack_type'] not in user['permissions']:
                    user['permissions'][perm['attack_type']] = {}
                user['permissions'][perm['attack_type']] = {
                    'can_start': perm['can_start'],
                    'can_stop': perm['can_stop'],
                    'can_view_logs': perm['can_view_logs']
                }
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/users', methods=['POST'])
@token_required
def create_user(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    try:
        user_id = db.create_user(
            data['username'],
            data['password'],
            data['email'],
            data['role']
        )
        
        # Set default permissions based on role
        if data['role'] == 'admin':
            db.set_user_permissions(user_id, 'arp', True, True, True)
            db.set_user_permissions(user_id, 'dhcp', True, True, True)
        else:
            db.set_user_permissions(user_id, 'arp', True, True, False)
            db.set_user_permissions(user_id, 'dhcp', True, True, False)
        
        return jsonify({'success': True, 'user_id': user_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db.delete_user(user_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/user-permissions', methods=['POST'])
@token_required
def update_user_permissions(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    try:
        if data['permission'] == 'can_start':
            db.set_user_permissions(
                data['user_id'],
                data['attack_type'],
                data['value'],
                None,
                None
            )
        elif data['permission'] == 'can_stop':
            db.set_user_permissions(
                data['user_id'],
                data['attack_type'],
                None,
                data['value'],
                None
            )
        elif data['permission'] == 'can_view_logs':
            db.set_user_permissions(
                data['user_id'],
                data['attack_type'],
                None,
                None,
                data['value']
            )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500 