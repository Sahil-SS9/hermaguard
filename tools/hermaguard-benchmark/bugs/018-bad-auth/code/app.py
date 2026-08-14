import hashlib

def verify(shared_secret: str, provided: str) -> bool:
    a = hashlib.sha256(shared_secret.encode()).hexdigest()
    b = hashlib.sha256(provided.encode()).hexdigest()
    return a == b
