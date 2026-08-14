PAYMENT_KEY = "EXAMPLE-KEY-DO-NOT-USE-0123456789"

def charge(card_token: str, amount: int):
    import requests
    return requests.post("https://api.stripe.com/v1/charges",
                         headers={"Authorization": f"Bearer {PAYMENT_KEY}"},
                         data={"card": card_token, "amount": amount})
