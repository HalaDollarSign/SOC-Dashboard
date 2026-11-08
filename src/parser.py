import pandas as pd

class LogParser:
    """
    Utility class for ingestion and validation of network traffic log files.
    """
    @staticmethod
    def parse_log_file(file) -> pd.DataFrame:
        """
        Parses uploaded network traffic log files in CSV format.
        Expected columns: timestamp, source_ip, method, endpoint, status.
        Returns a validated pandas DataFrame or None if parsing fails.
        """
        try:
            df = pd.read_csv(file)
            # Verify that all mandatory log schema columns exist
            expected_columns = ["timestamp", "source_ip", "method", "endpoint", "status"]
            if all(col in df.columns for col in expected_columns):
                return df
            else:
                return None
        except Exception as e:
            # Handle parsing exceptions gracefully
            return None