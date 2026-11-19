def find_order(conn, ref: str):
    return conn.execute("SELECT * FROM orders WHERE ref = '" + ref + "'").fetchall()
