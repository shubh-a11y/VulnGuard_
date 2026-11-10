import os

def check_service(service_name: str) -> str:
    # Command injection vulnerability via os.popen
    cmd = f"echo status for service: {service_name}"
    stream = os.popen(cmd)
    output = stream.read()
    stream.close()
    return output.strip()
