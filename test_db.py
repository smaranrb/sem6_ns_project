import os
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor

# Manually read .env file
env_path = Path('.') / '.env'
print(f"Looking for .env file at: {env_path.absolute()}")

try:
    print("Contents of .env file:")
    with open(env_path, 'r') as f:
        env_contents = f.read()
        print(env_contents)
        
    # Parse .env file manually
    env_vars = {}
    for line in env_contents.splitlines():
        if line and '=' in line:
            key, value = line.split('=', 1)
            os.environ[key] = value
            env_vars[key] = value

    print("\nEnvironment variables loaded manually:")
    for key, value in env_vars.items():
        print(f"{key}: {value}")
    
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
    
    print("\nDB_CONFIG:", db_config)
    
    try:
        print("\nAttempting to connect to PostgreSQL...")
        conn = psycopg2.connect(**db_config)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        print("Connection successful!")
        
        # Check if we can execute a simple query
        cur.execute("SELECT 1 as test")
        result = cur.fetchone()
        print("Query result:", result)
        
        # Close connection
        cur.close()
        conn.close()
        print("Connection closed.")
    except Exception as e:
        print("Error connecting to database:", str(e))
except Exception as e:
    print(f"Error reading .env file: {str(e)}") 