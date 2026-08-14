def change_email(request):
    if request.method in ("GET", "POST"):
        u = db.get_user(request.args["user"])
        u.email = request.args["email"]
        u.save()
