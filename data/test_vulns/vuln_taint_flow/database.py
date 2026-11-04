import sqlite3

class Database:
    def __init__(self):
        # In a real app this would connect to a persistent DB
        self.conn = sqlite3.connect(':memory:')
        self._setup()
        
    def _setup(self):
        cursor = self.conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, status TEXT)")
        cursor.execute("INSERT INTO users (status) VALUES ('active')")
        self.conn.commit()

    def update_user_status(self, new_status: str):
        """
        Updates the status of user ID 1.
        """
        cursor = self.conn.cursor()
        
        # VULNERABILITY CHAIN: Sink
        # The database blindly interpolates the tainted data into the SQL string.
        # This completes the cross-file SQL injection vulnerability chain.
        
        query = f"UPDATE users SET status = '{new_status}' WHERE id = 1"
        print(f"[Database] Executing: {query}")
        
        try:
            cursor.executescript(query)
            self.conn.commit()
            print("[Database] Update successful.")
        except Exception as e:
            print(f"[Database] Error: {e}")
