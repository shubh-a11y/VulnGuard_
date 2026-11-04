# This is the entry point that accepts raw user input

from data.test_vulns.vuln_taint_flow.processor import DataProcessor

def handle_request(raw_data: str):
    """
    Entry point for user requests. 
    Receives untrusted data from the network/user.
    """
    print(f"[InputHandler] Received raw data: {raw_data}")
    
    # VULNERABILITY CHAIN: Source
    # The handler passes the raw untrusted input directly to the processor
    # without doing any validation or sanitization.
    
    processor = DataProcessor()
    processor.process(raw_data)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        handle_request(sys.argv[1])
