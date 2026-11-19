def withdraw(conn, user_id: int, amount: int):
    cur = conn.execute(
        "UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
        (amount, user_id, amount))
    if cur.rowcount != 1:
        raise ValueError("insufficient funds")
    conn.commit()
