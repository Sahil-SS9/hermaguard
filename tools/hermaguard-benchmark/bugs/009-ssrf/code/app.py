import requests

def send_webhook(url: str, payload: dict):
    # user-supplied URL fetched without validation
    requests.post(url, json=payload, timeout=5)
