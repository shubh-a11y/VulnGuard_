import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: SQL Injection via string concatenation
    # If username is "admin' --", the query becomes:
    # SELECT * FROM users WHERE username = 'admin' --'
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    
    return result

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(get_user(sys.argv[1]))
