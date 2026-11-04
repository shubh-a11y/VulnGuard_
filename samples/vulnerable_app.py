import os
import sys

def ping_server(hostname: str):
    """
    Ping a server to check if it's alive.
    VULNERABLE: Uses os.system with untrusted user input without sanitization.
    """
    command = f"ping -c 1 {hostname}"
    # Execute the command
    result = os.system(command)
    
    if result == 0:
        return "Server is up!"
    else:
        return "Server is down or unreachable."

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(ping_server(sys.argv[1]))
    else:
        print("Usage: python vulnerable_app.py <hostname>")
