import sqlite3

def search_products(category: str, max_price: float, db_path: str = "shop.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Safe parameterized query
    query = "SELECT id, name, category, price FROM items WHERE category = ? AND price <= ?"
    cursor.execute(query, (category, max_price))
    rows = cursor.fetchall()
    conn.close()
    return rows

