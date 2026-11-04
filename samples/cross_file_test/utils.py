import subprocess

def run_command_unsafe(cmd: str):
    """
    Executes a system command without any sanitization.
    This is highly vulnerable to command injection.
    """
    # Shell=True allows operators like ;, &&, || to execute multiple commands
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
