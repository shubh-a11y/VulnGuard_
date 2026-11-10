import subprocess

def execute_diagnostic(target: str) -> str:
    # Command injection vulnerability via shell=True
    cmd = f"echo Running diagnostic on {target}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.stdout.strip()
