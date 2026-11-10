import sqlite3

def get_user(username: str, db_path: str = "users.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Safe parameterized query
    query = "SELECT id, username, role FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    rows = cursor.fetchall()
    conn.close()
    return rows

