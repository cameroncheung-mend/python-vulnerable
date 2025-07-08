import os
import sqlite3

# --- Hardcoded Credentials (Vulnerability 1) ---
# Storing sensitive information directly in the code is a major security risk.
# This should be loaded from secure environment variables or a secrets management system.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = "e10adc3949ba59abbe56e057f20f883e" # MD5 hash of '123456' - still bad!

def init_db():
    """Initializes a simple SQLite database for demonstration."""
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized.")

def login_user_vulnerable(username, password):
    """
    Vulnerability 2: SQL Injection
    This function is vulnerable to SQL injection because it directly concatenates
    user input into the SQL query string without proper sanitization or
    parameterized queries.
    """
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()

    # BAD PRACTICE: Directly concatenating user input into the query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}';"
    print(f"Executing vulnerable query: {query}")

    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            print(f"Login successful for user: {user[1]}")
            return user
        else:
            print("Invalid username or password.")
            return None
    except sqlite3.Error as e:
        print(f"Database error during login: {e}")
        return None
    finally:
        conn.close()

def execute_command_vulnerable(command):
    """
    Vulnerability 3: Command Injection
    This function uses os.system with unsanitized user input, allowing an
    attacker to execute arbitrary system commands.
    """
    print(f"Attempting to execute command: '{command}'")
    try:
        # BAD PRACTICE: Directly executing user input as a system command
        os.system(command)
        print("Command executed (potentially).")
    except Exception as e:
        print(f"Error executing command: {e}")

if __name__ == "__main__":
    init_db()

    # Insert a dummy admin user for demonstration purposes
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (ADMIN_USERNAME, ADMIN_PASSWORD_HASH, 'admin'))
        conn.commit()
    finally:
        conn.close()

    print("\n--- Demonstrating SQL Injection (Login) ---")
    login_user_vulnerable("admin", ADMIN_PASSWORD_HASH)

    # SQL Injection payload to bypass authentication
    print("\n--- SQL Injection Attack Attempt (Login Bypass) ---")
    sql_payload_login = "' OR 1=1 --"
    login_user_vulnerable("anyuser", sql_payload_login) # This will likely log in as the first user

    print("\n--- Demonstrating Command Injection ---")
    # Harmless command for demonstration
    execute_command_vulnerable("echo Hello from vulnerable app!")

    # Malicious command injection payload (Linux/macOS example)
    print("\n--- Command Injection Attack Attempt (Listing files) ---")
    malicious_command = "ls -la" # On Windows, try "dir"
    execute_command_vulnerable(malicious_command)

    print("\n--- Cleanup ---")
    try:
        os.remove('vulnerable_app.db')
        print("Cleaned up vulnerable_app.db")
    except OSError as e:
        print(f"Error during cleanup: {e}")
