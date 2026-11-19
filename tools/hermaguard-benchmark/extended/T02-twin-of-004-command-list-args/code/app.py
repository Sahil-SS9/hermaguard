import subprocess

def ping_host(host: str) -> bytes:
    return subprocess.check_output(["ping", "-c", "1", "--", host])
