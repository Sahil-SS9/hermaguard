def parse(stream):
    records = []
    while True:
        line = stream.readline()
        if not line:
            break
        records.append(json.loads(line))
    return records
