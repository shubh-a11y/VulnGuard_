import os
from utils import run_command_unsafe

def process_user_input(user_id: str):
    """
    Processes the user input.
    The vulnerability is cross-file: the user_id flows into run_command_unsafe
    which is imported from utils.py.
    """
    # The command injection happens because user_id is unsanitized and passed 
    # to a vulnerable helper function.
    output = run_command_unsafe(f"echo Processing user {user_id}")
    return output

# --- Red Agent Test Harness ---
# (The Red Agent uses this block to verify if the vulnerability exists)
if __name__ == "__main__":
    # Test case to demonstrate command injection
    malicious_input = "; touch /tmp/cross_file_injection"
    
    if os.path.exists("/tmp/cross_file_injection"):
        os.remove("/tmp/cross_file_injection")
        
    process_user_input(malicious_input)
    
    if os.path.exists("/tmp/cross_file_injection"):
        print("DEFECT_TRIGGERED")
        os.remove("/tmp/cross_file_injection")
    else:
        print("DEFECT_NOT_TRIGGERED")
