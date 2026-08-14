def reset_password(request, user_id: int):
    new_pw = request.json["password"]
    db.execute("UPDATE users SET pw = ? WHERE id = ?", (hash(new_pw), user_id))
    db.commit()
