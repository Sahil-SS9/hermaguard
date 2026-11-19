def refund_report(rows):
    return sum(r.amount for r in rows if r.amount > 0)
