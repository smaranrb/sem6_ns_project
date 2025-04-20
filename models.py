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

    def set_user_permissions(self, user_id, permissions):
        """Set user permissions"""
        for perm in permissions:
            self.cur.execute("""
                INSERT INTO user_permissions (user_id, attack_type, can_start, can_stop, can_view_logs)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, perm['attack_type'], perm['can_start'], perm['can_stop'], perm['can_view_logs']))
        self.conn.commit()

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
        """Get user's attack sessions"""
        self.cur.execute("""
            SELECT id, attack_type, start_time, end_time, status, parameters, affected_clients
            FROM attack_sessions
            WHERE user_id = %s
            ORDER BY start_time DESC
        """, (user_id,))
        return self.cur.fetchall()

    def close(self):
        """Close database connection"""
        self.cur.close()
        self.conn.close() 