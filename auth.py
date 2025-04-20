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