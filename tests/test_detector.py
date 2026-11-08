import pytest
import pandas as pd
import time
from io import StringIO
from src.detector import ThreatDetector
from src.parser import LogParser

def test_threat_detector_threshold():
    """Test if ThreatDetector correctly identifies threshold breaches and blacklists IPs."""
    detector = ThreatDetector(threshold=2, time_window=5)
    ip = "192.168.1.100"
    
    # First request - should be normal (False)
    assert detector.analyze_ip(ip) is False
    # Second request - should be normal (False)
    assert detector.analyze_ip(ip) is False
    # Third request - exceeds threshold (2), should trigger threat alert (True)
    assert detector.analyze_ip(ip) is True
    # Subsequent requests from blacklisted IP should remain blocked
    assert detector.analyze_ip(ip) is True

def test_manual_block_unblock():
    """Test manual IP blacklisting and unblocking methods."""
    detector = ThreatDetector()
    ip = "10.0.0.99"
    
    detector.block_ip(ip)
    assert ip in detector.blacklist
    assert detector.analyze_ip(ip) is True
    
    detector.unblock_ip(ip)
    assert ip not in detector.blacklist

def test_log_parser_valid_data():
    """Test LogParser with valid CSV log format."""
    csv_data = "timestamp,source_ip,method,endpoint,status\n2026-11-08 12:00:01,192.168.1.50,GET,/,200"
    file_obj = StringIO(csv_data)
    
    df = LogParser.parse_log_file(file_obj)
    assert df is not None
    assert "source_ip" in df.columns
    assert len(df) == 1
    assert df.loc[0, "source_ip"] == "192.168.1.50"

def test_log_parser_invalid_data():
    """Test LogParser with invalid schema columns."""
    csv_data = "bad_col1,bad_col2\nval1,val2"
    file_obj = StringIO(csv_data)
    
    df = LogParser.parse_log_file(file_obj)
    assert df is None