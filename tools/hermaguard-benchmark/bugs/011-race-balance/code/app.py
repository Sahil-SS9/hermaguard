def withdraw(conn, user_id: int, amount: int):
    row = conn.execute("SELECT balance FROM accounts WHERE id = ?", (user_id,)).fetchone()
    if row[0] < amount:
        raise ValueError("insufficient funds")
    conn.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, user_id))
    conn.commit()
