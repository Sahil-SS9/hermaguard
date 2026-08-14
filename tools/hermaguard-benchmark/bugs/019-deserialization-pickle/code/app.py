import pickle

def load_state(body: bytes):
    return pickle.loads(body)
