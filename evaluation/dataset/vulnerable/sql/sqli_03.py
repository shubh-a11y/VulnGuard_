import sqlite3

def filter_orders(status: str, db_path: str = "orders.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # SQL Injection via .format()
    query = "SELECT order_id, customer, status, total FROM orders WHERE status = '{}'".format(status)
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows

