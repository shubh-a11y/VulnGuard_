import re

def check_service(service_name: str) -> str:
    # Safe implementation: validation and pure Python string formatting
    if not re.match(r"^[a-zA-Z0-9_\-]+$", service_name):
        raise ValueError(f"Invalid service name: {service_name}")
    return f"status for service: {service_name}"
