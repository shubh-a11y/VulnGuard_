import re
import subprocess
import sys

def ping_host(hostname: str) -> int:
    # Safe implementation: validation and argv list without shell
    if not re.match(r"^[a-zA-Z0-9.\-]+$", hostname):
        raise ValueError("Invalid hostname format")
    flag = "-n" if sys.platform == "win32" else "-c"
    proc = subprocess.run(["ping", flag, "1", hostname], shell=False, capture_output=True, text=True)
    return proc.returncode
