import os
import sqlite3

def execute_system_command(user_input: str):
    command = f"echo {user_input}"
    return os.system(command)

def get_user_by_name(username: str):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except Exception as e:
        return str(e)
    finally:
        conn.close()

def read_user_file(filename: str):
    base_dir = "/var/www/uploads/"
    file_path = base_dir + filename
    
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return str(e)

def safe_math_add(a: int, b: int) -> int:
    return a + b
