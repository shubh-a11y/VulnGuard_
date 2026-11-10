import os
import sys

def ping_host(hostname: str) -> int:
    # Command injection vulnerability via os.system
    flag = "-n" if sys.platform == "win32" else "-c"
    command = f"ping {flag} 1 {hostname}"
    return os.system(command)
