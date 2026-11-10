import sqlite3

def get_user(username: str, db_path: str = "users.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # SQL Injection via string concatenation
    query = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows

