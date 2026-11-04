import os

def ping_host(hostname):
    # VULNERABILITY: Command Injection
    # If hostname is "localhost; cat /etc/passwd", it executes both commands.
    command = f"ping -c 1 {hostname}"
    
    print(f"Executing: {command}")
    # os.system executes the command in a subshell, allowing shell metacharacters
    result = os.system(command)
    
    return result

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        ping_host(sys.argv[1])
