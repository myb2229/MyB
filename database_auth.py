"""
Database Authentication Module
Supports both SQLite and PostgreSQL for user authentication
"""

import sqlite3
import hashlib
import secrets
from typing import Optional, Tuple
import psycopg2
from psycopg2 import Error


class SQLiteAuth:
    """SQLite Database Authentication"""
    
    def __init__(self, db_path: str = "users.db"):
        """Initialize SQLite database connection"""
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create users table if it doesn't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()
            print("✓ SQLite database initialized")
        except sqlite3.Error as e:
            print(f"✗ Database error: {e}")
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return password_hash, salt
    
    def add_user(self, username: str, password: str) -> bool:
        """Add new user to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            password_hash, salt = self.hash_password(password)
            
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            conn.commit()
            conn.close()
            print(f"✓ User '{username}' added successfully")
            return True
        except sqlite3.IntegrityError:
            print(f"✗ User '{username}' already exists")
            return False
        except sqlite3.Error as e:
            print(f"✗ Database error: {e}")
            return False
    
    def get_user_password(self, username: str) -> Optional[dict]:
        """Get user password hash and salt from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT username, password_hash, salt FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    "username": result[0],
                    "password_hash": result[1],
                    "salt": result[2]
                }
            return None
        except sqlite3.Error as e:
            print(f"✗ Database error: {e}")
            return None
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verify user password"""
        user = self.get_user_password(username)
        if not user:
            print(f"✗ User '{username}' not found")
            return False
        
        password_hash, _ = self.hash_password(password, user['salt'])
        
        if password_hash == user['password_hash']:
            print(f"✓ Password verified for user '{username}'")
            return True
        print(f"✗ Invalid password for user '{username}'")
        return False
    
    def list_all_users(self):
        """List all users (without passwords)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT id, username, created_at FROM users")
            results = cursor.fetchall()
            conn.close()
            
            print("\n--- All Users ---")
            for row in results:
                print(f"ID: {row[0]}, Username: {row[1]}, Created: {row[2]}")
            return results
        except sqlite3.Error as e:
            print(f"✗ Database error: {e}")
            return []


class PostgreSQLAuth:
    """PostgreSQL Database Authentication"""
    
    def __init__(self, host: str, database: str, user: str, password: str, port: int = 5432):
        """Initialize PostgreSQL database connection"""
        self.connection_params = {
            'host': host,
            'database': database,
            'user': user,
            'password': password,
            'port': port
        }
        self.init_database()
    
    def init_database(self):
        """Create users table if it doesn't exist"""
        try:
            conn = psycopg2.connect(**self.connection_params)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            cursor.close()
            conn.close()
            print("✓ PostgreSQL database initialized")
        except Error as e:
            print(f"✗ Database error: {e}")
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return password_hash, salt
    
    def add_user(self, username: str, password: str) -> bool:
        """Add new user to database"""
        try:
            conn = psycopg2.connect(**self.connection_params)
            cursor = conn.cursor()
            
            password_hash, salt = self.hash_password(password)
            
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                (username, password_hash, salt)
            )
            conn.commit()
            cursor.close()
            conn.close()
            print(f"✓ User '{username}' added successfully")
            return True
        except Error as e:
            print(f"✗ Database error: {e}")
            return False
    
    def get_user_password(self, username: str) -> Optional[dict]:
        """Get user password hash and salt from database"""
        try:
            conn = psycopg2.connect(**self.connection_params)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT username, password_hash, salt FROM users WHERE username = %s",
                (username,)
            )
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if result:
                return {
                    "username": result[0],
                    "password_hash": result[1],
                    "salt": result[2]
                }
            return None
        except Error as e:
            print(f"✗ Database error: {e}")
            return None
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verify user password"""
        user = self.get_user_password(username)
        if not user:
            print(f"✗ User '{username}' not found")
            return False
        
        password_hash, _ = self.hash_password(password, user['salt'])
        
        if password_hash == user['password_hash']:
            print(f"✓ Password verified for user '{username}'")
            return True
        print(f"✗ Invalid password for user '{username}'")
        return False
    
    def list_all_users(self):
        """List all users (without passwords)"""
        try:
            conn = psycopg2.connect(**self.connection_params)
            cursor = conn.cursor()
            
            cursor.execute("SELECT id, username, created_at FROM users")
            results = cursor.fetchall()
            cursor.close()
            conn.close()
            
            print("\n--- All Users ---")
            for row in results:
                print(f"ID: {row[0]}, Username: {row[1]}, Created: {row[2]}")
            return results
        except Error as e:
            print(f"✗ Database error: {e}")
            return []


# Example usage
if __name__ == "__main__":
    # === SQLite Example ===
    print("=" * 50)
    print("SQLite Authentication Example")
    print("=" * 50)
    
    sqlite_auth = SQLiteAuth("users_sqlite.db")
    
    # Add users
    sqlite_auth.add_user("john_doe", "password123")
    sqlite_auth.add_user("jane_smith", "securepass456")
    
    # Get user credentials
    user = sqlite_auth.get_user_password("john_doe")
    if user:
        print(f"\nUser: {user['username']}")
        print(f"Password Hash: {user['password_hash'][:20]}...")
        print(f"Salt: {user['salt'][:20]}...")
    
    # Verify password
    sqlite_auth.verify_password("john_doe", "password123")
    sqlite_auth.verify_password("john_doe", "wrongpassword")
    
    # List all users
    sqlite_auth.list_all_users()
    
    
    # === PostgreSQL Example (uncomment if PostgreSQL is set up) ===
    # print("\n" + "=" * 50)
    # print("PostgreSQL Authentication Example")
    # print("=" * 50)
    # 
    # pg_auth = PostgreSQLAuth(
    #     host='localhost',
    #     database='mydb',
    #     user='postgres',
    #     password='your_password'
    # )
    # 
    # pg_auth.add_user("alice_wonder", "alice_pass123")
    # pg_auth.add_user("bob_builder", "bob_pass456")
    # 
    # user = pg_auth.get_user_password("alice_wonder")
    # if user:
    #     print(f"\nUser: {user['username']}")
    #     print(f"Password Hash: {user['password_hash'][:20]}...")
    # 
    # pg_auth.verify_password("alice_wonder", "alice_pass123")
    # pg_auth.list_all_users()
