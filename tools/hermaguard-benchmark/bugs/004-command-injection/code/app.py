import subprocess

def ping_host(host: str) -> bytes:
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)
