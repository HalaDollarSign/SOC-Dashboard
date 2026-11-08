import time

class ThreatDetector:
    """
    Handles real-time network traffic analysis, sliding-window rate limiting,
    and IP blacklisting to mitigate potential DDoS or brute-force attacks.
    """
    def __init__(self, threshold=5, time_window=10):
        self.threshold = threshold  # Maximum allowed requests per time window
        self.time_window = time_window  # Time window duration in seconds
        self.request_history = {}  # Dictionary tracking request timestamps per IP
        self.blacklist = set()  # Set containing blocked source IP addresses

    def analyze_ip(self, ip_address: str) -> bool:
        """
        Evaluates incoming traffic from a source IP address against threshold rules
        and blacklist status. Returns True if an anomaly or threat is detected.
        """
        # Check if the IP is already blacklisted
        if ip_address in self.blacklist:
            return True

        current_time = time.time()
        
        # Initialize history buffer for a new IP address
        if ip_address not in self.request_history:
            self.request_history[ip_address] = []

        # Purge timestamps outside the active time window (sliding window mechanism)
        self.request_history[ip_address] = [
            t for t in self.request_history[ip_address] 
            if current_time - t < self.time_window
        ]

        # Register the current request timestamp
        self.request_history[ip_address].append(current_time)

        # Evaluate threshold breach and automatically trigger blacklisting
        if len(self.request_history[ip_address]) > self.threshold:
            self.blacklist.add(ip_address)
            return True  # Threat detected!
            
        return False

    def block_ip(self, ip_address: str):
        """Manually adds a source IP address to the security blacklist."""
        self.blacklist.add(ip_address)

    def unblock_ip(self, ip_address: str):
        """Removes a source IP address from the security blacklist."""
        if ip_address in self.blacklist:
            self.blacklist.remove(ip_address)