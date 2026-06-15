def get_user_email(cur, user_id: int) -> str:
    cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return row[0]
