import sqlite3

def get_user_by_name(username: str):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cur.execute(query)
    return cur.fetchone()
