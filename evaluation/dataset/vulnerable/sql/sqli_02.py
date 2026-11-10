import sqlite3

def search_products(category: str, max_price: float, db_path: str = "shop.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # SQL Injection via f-string formatting
    query = f"SELECT id, name, category, price FROM items WHERE category = '{category}' AND price <= {max_price}"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows

