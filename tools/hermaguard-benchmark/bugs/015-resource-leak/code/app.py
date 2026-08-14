def read_config(path):
    f = open(path)
    data = json.load(f)
    return data
