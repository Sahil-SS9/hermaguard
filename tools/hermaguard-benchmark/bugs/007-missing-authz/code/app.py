def delete_user(session_user, target_id: int):
    # authn done upstream, but no role check
    db.execute("DELETE FROM users WHERE id = ?", (target_id,))
    db.commit()
    return {"ok": True}
