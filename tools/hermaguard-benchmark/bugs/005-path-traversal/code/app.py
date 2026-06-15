def read_doc(name: str) -> str:
    with open("/var/docs/" + name) as f:
        return f.read()
