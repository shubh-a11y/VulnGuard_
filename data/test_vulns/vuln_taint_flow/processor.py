from data.test_vulns.vuln_taint_flow.database import Database

class DataProcessor:
    def __init__(self):
        self.db = Database()
        
    def process(self, data: str):
        """
        Transforms data. Assumes data is already safe.
        """
        print(f"[Processor] Processing data length: {len(data)}")
        
        # VULNERABILITY CHAIN: Propagator
        # The processor does some business logic (like lowercasing)
        # but fails to validate or sanitize the data.
        # It blindly passes the tainted data to the sink.
        
        transformed_data = data.strip().lower()
        self.db.update_user_status(transformed_data)
