def refund(account, amount: int):
    # amount is never checked: a negative value adds money
    account.balance -= amount
    return account.balance
