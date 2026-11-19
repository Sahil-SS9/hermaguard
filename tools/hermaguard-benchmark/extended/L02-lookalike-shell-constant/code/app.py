import subprocess

def disk_usage() -> bytes:
    return subprocess.check_output("df -h /", shell=True)
