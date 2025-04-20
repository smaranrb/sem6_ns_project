import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
from datetime import datetime
import json
from config import DB_CONFIG

class Database:
    def __init__(self):
        self.conn = psycopg2.connect(**DB_CONFIG)
        self.cur = self.conn.cursor(cursor_factory=RealDictCursor)
        self.create_tables()

    def create_tables(self):
        """Create necessary database tables if they don't exist"""
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                role VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS user_permissions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                attack_type VARCHAR(20) NOT NULL,
                can_start BOOLEAN DEFAULT FALSE,
                can_stop BOOLEAN DEFAULT FALSE,
                can_view_logs BOOLEAN DEFAULT FALSE
            );

            CREATE TABLE IF NOT EXISTS attack_sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                attack_type VARCHAR(20) NOT NULL,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                status VARCHAR(20) NOT NULL,
                parameters JSONB,
                affected_clients JSONB
            );

            CREATE TABLE IF NOT EXISTS system_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                action VARCHAR(50) NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            );
        """)
        self.conn.commit()

    def create_user(self, username, password, email, role):
        """Create a new user"""
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        self.cur.execute("""
            INSERT INTO users (username, password_hash, email, role)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (username, password_hash, email, role))
        user_id = self.cur.fetchone()['id']
        self.conn.commit()
        return user_id

    def set_user_permissions(self, user_id, attack_type=None, can_start=None, can_stop=None, can_view_logs=None, permissions=None):
        """Set user permissions
        Can be called in two ways:
        1. With individual permission parameters: user_id, attack_type, can_start, can_stop, can_view_logs
        2. With a list of permission dictionaries: user_id, permissions=[{attack_type, can_start, can_stop, can_view_logs}]
        """
        try:
            if permissions is not None:
                # Bulk update with list of permissions
                # First, delete existing permissions for this user
                self.cur.execute("DELETE FROM user_permissions WHERE user_id = %s", (user_id,))
                
                # Then insert new permissions
                for perm in permissions:
                    self.cur.execute("""
                        INSERT INTO user_permissions (user_id, attack_type, can_start, can_stop, can_view_logs)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (user_id, perm['attack_type'], perm['can_start'], perm['can_stop'], perm['can_view_logs']))
            else:
                # Individual permission update
                # First, check if permission exists
                self.cur.execute("""
                    SELECT * FROM user_permissions 
                    WHERE user_id = %s AND attack_type = %s
                """, (user_id, attack_type))
                
                existing = self.cur.fetchone()
                
                if existing:
                    # Update existing permission
                    update_fields = []
                    update_values = []
                    
                    if can_start is not None:
                        update_fields.append("can_start = %s")
                        update_values.append(can_start)
                    if can_stop is not None:
                        update_fields.append("can_stop = %s")
                        update_values.append(can_stop)
                    if can_view_logs is not None:
                        update_fields.append("can_view_logs = %s")
                        update_values.append(can_view_logs)
                    
                    if update_fields:
                        query = f"""
                            UPDATE user_permissions 
                            SET {', '.join(update_fields)}
                            WHERE user_id = %s AND attack_type = %s
                        """
                        update_values.extend([user_id, attack_type])
                        self.cur.execute(query, tuple(update_values))
                else:
                    # Insert new permission
                    self.cur.execute("""
                        INSERT INTO user_permissions (user_id, attack_type, can_start, can_stop, can_view_logs)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (user_id, attack_type, 
                         can_start if can_start is not None else False,
                         can_stop if can_stop is not None else False,
                         can_view_logs if can_view_logs is not None else False))
            
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e

    def verify_user(self, username, password):
        """Verify user credentials"""
        self.cur.execute("""
            SELECT id, username, password_hash, role, is_active, login_attempts, locked_until
            FROM users
            WHERE username = %s
        """, (username,))
        user = self.cur.fetchone()

        if not user:
            return None

        # Check if account is locked
        if user['locked_until'] and user['locked_until'] > datetime.now():
            return None

        # Verify password
        if bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            # Reset login attempts on successful login
            self.cur.execute("""
                UPDATE users
                SET login_attempts = 0, last_login = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (user['id'],))
            self.conn.commit()
            return user
        else:
            # Increment failed login attempts
            self.cur.execute("""
                UPDATE users
                SET login_attempts = login_attempts + 1
                WHERE id = %s
                RETURNING login_attempts
            """, (user['id'],))
            attempts = self.cur.fetchone()['login_attempts']
            
            # Lock account if too many failed attempts
            if attempts >= 5:  # Assuming max attempts is 5
                self.cur.execute("""
                    UPDATE users
                    SET locked_until = CURRENT_TIMESTAMP + INTERVAL '5 minutes'
                    WHERE id = %s
                """, (user['id'],))
            self.conn.commit()
            return None

    def get_user_permissions(self, user_id):
        """Get user permissions"""
        self.cur.execute("""
            SELECT attack_type, can_start, can_stop, can_view_logs
            FROM user_permissions
            WHERE user_id = %s
        """, (user_id,))
        return self.cur.fetchall()

    def log_action(self, user_id, action, details):
        """Log user action"""
        self.cur.execute("""
            INSERT INTO system_logs (user_id, action, details)
            VALUES (%s, %s, %s)
        """, (user_id, action, details))
        self.conn.commit()

    def create_attack_session(self, user_id, attack_type, parameters):
        """Create a new attack session"""
        self.cur.execute("""
            INSERT INTO attack_sessions (user_id, attack_type, status, parameters)
            VALUES (%s, %s, 'running', %s)
            RETURNING id
        """, (user_id, attack_type, json.dumps(parameters)))
        session_id = self.cur.fetchone()['id']
        self.conn.commit()
        return session_id

    def update_attack_session(self, session_id, status, affected_clients=None):
        """Update attack session status"""
        if affected_clients:
            self.cur.execute("""
                UPDATE attack_sessions
                SET status = %s, end_time = CURRENT_TIMESTAMP, affected_clients = %s
                WHERE id = %s
            """, (status, json.dumps(affected_clients), session_id))
        else:
            self.cur.execute("""
                UPDATE attack_sessions
                SET status = %s, end_time = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (status, session_id))
        self.conn.commit()

    def get_user_sessions(self, user_id):
        """Get all attack sessions for a user"""
        try:
            self.cur.execute("""
                SELECT 
                    id,
                    attack_type,
                    parameters,
                    affected_clients,
                    start_time,
                    end_time,
                    status
                FROM attack_sessions
                WHERE user_id = %s
                ORDER BY start_time DESC
                LIMIT 100
            """, (user_id,))
            sessions = self.cur.fetchall()
            return sessions
        except Exception as e:
            self.conn.rollback()  # Rollback the failed transaction
            raise e

    def get_user_logs(self, user_id):
        """Get all activity logs for a user"""
        try:
            self.cur.execute("""
                SELECT action, details, timestamp as created_at
                FROM system_logs
                WHERE user_id = %s
                ORDER BY timestamp DESC
                LIMIT 100
            """, (user_id,))
            logs = self.cur.fetchall()
            return logs
        except Exception as e:
            self.conn.rollback()  # Rollback the failed transaction
            raise e

    def get_all_users(self):
        """Get all users with their permissions"""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get all users
            cur.execute("""
                SELECT id, username, email, role, created_at, last_login, is_active
                FROM users
                ORDER BY created_at DESC
            """)
            users = cur.fetchall()
            
            # Get permissions for each user
            for user in users:
                cur.execute("""
                    SELECT attack_type, can_start, can_stop, can_view_logs
                    FROM user_permissions
                    WHERE user_id = %s
                """, (user['id'],))
                permissions = cur.fetchall()
                
                # Organize permissions by attack type
                user['permissions'] = {}
                for perm in permissions:
                    user['permissions'][perm['attack_type']] = {
                        'can_start': perm['can_start'],
                        'can_stop': perm['can_stop'],
                        'can_view_logs': perm['can_view_logs']
                    }
            
            return users

    def delete_user(self, user_id):
        """Delete a user and all associated data"""
        with self.conn.cursor() as cur:
            # Delete user permissions
            cur.execute("DELETE FROM user_permissions WHERE user_id = %s", (user_id,))
            
            # Delete attack sessions
            cur.execute("DELETE FROM attack_sessions WHERE user_id = %s", (user_id,))
            
            # Delete system logs
            cur.execute("DELETE FROM system_logs WHERE user_id = %s", (user_id,))
            
            # Delete the user
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            
            self.conn.commit()

    def close(self):
        """Close database connection"""
        self.cur.close()
        self.conn.close() 