def export_all(request, db):
    # no authentication of the caller
    return db.dump_orders()
