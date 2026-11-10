import sqlite3

ALLOWED_STATUSES = {"pending", "processing", "completed", "cancelled"}

def filter_orders(status: str, db_path: str = "orders.db"):
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"Invalid status filter: {status}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Safe query using whitelist validated parameter
    query = "SELECT order_id, customer, status, total FROM orders WHERE status = ?"
    cursor.execute(query, (status,))
    rows = cursor.fetchall()
    conn.close()
    return rows

