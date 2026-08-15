# Deliberately broken sample: a live-looking API key committed to source.
# NOTE: the value is an obviously-fake placeholder (marker, not a real key
# format) so secret scanners do not flag the corpus; the CWE-798 pattern
# (credential hardcoded in source) is what the benchmark tests for.
PAYMENT_KEY = "EXAMPLE-KEY-DO-NOT-USE-0123456789"

def charge(card_token: str, amount: int):
    import requests
    return requests.post("https://api.example-payments.invalid/v1/charges",
                         headers={"Authorization": f"Bearer {PAYMENT_KEY}"},
                         data={"card": card_token, "amount": amount})
