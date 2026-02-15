#!/usr/bin/env python3
"""
Synthetic Log Generator for signaltrace
Generates realistic Zscaler-style web proxy logs in JSONL format
"""

import json
import random
from datetime import datetime, timedelta
from typing import List, Dict

# Seed for reproducibility
random.seed(42)

# Configuration
BASE_TIME = datetime(2026, 2, 14, 8, 0, 0)  # Start at 8 AM UTC

# Normal user IPs (internal network)
NORMAL_IPS = [
    "192.168.1.100",
    "192.168.1.101", 
    "192.168.1.102",
    "192.168.1.103",
    "192.168.1.104",
    "192.168.1.105",
    "192.168.1.106",
    "192.168.1.107",
    "192.168.1.108",
    "192.168.1.109",
]

# Normal destinations
NORMAL_URLS = [
    "https://google.com/search",
    "https://github.com/company/repo",
    "https://stackoverflow.com/questions/12345",
    "https://slack.com/api/chat.postMessage",
    "https://drive.google.com/file/d/abc123",
    "https://docs.google.com/document/d/xyz789",
    "https://mail.google.com/mail/u/0/",
    "https://calendar.google.com/calendar/r",
    "https://zoom.us/j/123456789",
    "https://atlassian.net/browse/PROJ-123",
    "https://aws.amazon.com/console",
    "https://portal.azure.com/",
    "https://app.datadog.com/dashboard",
    "https://linkedin.com/in/profile",
    "https://twitter.com/company",
]

# Normal user agents
NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

CATEGORIES = ["Business", "Technology", "Collaboration", "Productivity", "Social Media"]


def generate_baseline_log(offset_minutes: int) -> Dict:
    """Generate a single normal log entry"""
    timestamp = BASE_TIME + timedelta(minutes=offset_minutes)
    
    return {
        "time": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "clientip": random.choice(NORMAL_IPS),
        "user": f"user{random.randint(1, 10)}@company.com",
        "method": random.choice(["GET", "POST"]),
        "url": random.choice(NORMAL_URLS),
        "action": "ALLOW",
        "responsecode": random.choice([200, 200, 200, 304]),
        "requestsize": random.randint(500, 2000),
        "responsesize": random.randint(1000, 50000),
        "useragent": random.choice(NORMAL_USER_AGENTS),
        "category": random.choice(CATEGORIES),
    }


def generate_credential_stuffing() -> List[Dict]:
    """
    Anomaly Scenario A: Credential Stuffing
    - High requests_per_minute_peak (>100)
    - High deny_rate (>60%)
    - Repeated auth endpoint
    """
    logs = []
    attacker_ip = "203.0.113.45"
    
    # Burst of 150 requests in 1 minute window
    burst_start = 120  # 2 hours in (10:00 AM)
    
    for i in range(150):
        timestamp = BASE_TIME + timedelta(minutes=burst_start, seconds=i * 0.4)
        
        logs.append({
            "time": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "clientip": attacker_ip,
            "user": f"victim{i % 20}@company.com",  # Trying multiple users
            "method": "POST",
            "url": "https://company.com/api/auth/login",
            "action": "DENY" if i % 10 < 9 else "ALLOW",  # 90% fail rate
            "responsecode": 401 if i % 10 < 9 else 200,
            "requestsize": 512,
            "responsesize": 256,
            "useragent": "python-requests/2.28.0",
            "category": "Authentication",
        })
    
    return logs


def generate_data_exfiltration() -> List[Dict]:
    """
    Anomaly Scenario B: Data Exfiltration
    - High total_bytes_transferred (>50MB)
    - High off_hours_request_ratio (>70%)
    - Few but large transfers
    """
    logs = []
    insider_ip = "192.168.1.150"
    
    # Off-hours activity (2-4 AM UTC)
    off_hours_start = -6 * 60  # 6 hours before BASE_TIME (2 AM)
    
    for i in range(15):
        timestamp = BASE_TIME + timedelta(minutes=off_hours_start + i * 8)
        
        logs.append({
            "time": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "clientip": insider_ip,
            "user": "insider@company.com",
            "method": "GET",
            "url": f"https://dropbox.com/download/sensitive-data-{i}.zip",
            "action": "ALLOW",
            "responsecode": 200,
            "requestsize": 512,
            "responsesize": random.randint(3_000_000, 8_000_000),  # 3-8MB each
            "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "category": "File Sharing",
        })
    
    return logs


def generate_scanning() -> List[Dict]:
    """
    Anomaly Scenario C: Scanning Behavior
    - High unique_hosts_count (>20)
    - Short burst window
    - Moderate deny_rate
    """
    logs = []
    scanner_ip = "198.51.100.89"
    
    # Generate 50 requests to 30 different hosts in 10 minutes
    scan_start = 180  # 3 hours in (11:00 AM)
    
    # List of targets to scan
    targets = [
        f"http://10.0.{i}.{j}" for i in range(1, 6) for j in range(1, 7)
    ]
    
    for i, target in enumerate(targets):
        timestamp = BASE_TIME + timedelta(minutes=scan_start, seconds=i * 12)
        
        logs.append({
            "time": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "clientip": scanner_ip,
            "user": "scanner@external.com",
            "method": "GET",
            "url": f"{target}/",
            "action": "DENY" if i % 3 < 2 else "ALLOW",  # 66% deny rate
            "responsecode": 403 if i % 3 < 2 else 200,
            "requestsize": 256,
            "responsesize": 128,
            "useragent": "Nmap NSE",
            "category": "Scanning",
        })
    
    return logs


def generate_baseline_file(count: int, filename: str):
    """Generate baseline traffic file"""
    logs = []
    
    # Spread over 8 hours
    time_span_minutes = 8 * 60
    
    for i in range(count):
        offset = int((i / count) * time_span_minutes)
        # Add some randomness
        offset += random.randint(-5, 5)
        logs.append(generate_baseline_log(offset))
    
    # Sort by time
    logs.sort(key=lambda x: x["time"])
    
    # Write JSONL
    with open(filename, 'w') as f:
        for log in logs:
            f.write(json.dumps(log) + '\n')
    
    print(f"Generated {filename}: {len(logs)} events")


def generate_anomalous_file(anomaly_type: str, filename: str):
    """Generate file with specific anomaly type"""
    
    # Start with baseline
    baseline_logs = [generate_baseline_log(i * 5) for i in range(200)]
    
    # Add anomaly
    if anomaly_type == "credential_stuffing":
        anomaly_logs = generate_credential_stuffing()
    elif anomaly_type == "exfiltration":
        anomaly_logs = generate_data_exfiltration()
    elif anomaly_type == "scanning":
        anomaly_logs = generate_scanning()
    else:
        raise ValueError(f"Unknown anomaly type: {anomaly_type}")
    
    # Combine and sort
    all_logs = baseline_logs + anomaly_logs
    all_logs.sort(key=lambda x: x["time"])
    
    # Write JSONL
    with open(filename, 'w') as f:
        for log in all_logs:
            f.write(json.dumps(log) + '\n')
    
    print(f"Generated {filename}: {len(all_logs)} events ({len(anomaly_logs)} anomalous)")


if __name__ == "__main__":
    print("Generating synthetic Zscaler-style logs...")
    print()
    
    # Baseline files
    generate_baseline_file(1000, "data/baseline_small.jsonl")
    generate_baseline_file(3000, "data/baseline_medium.jsonl")
    generate_baseline_file(5000, "data/baseline_large.jsonl")
    
    print()
    
    # Anomalous files
    generate_anomalous_file("credential_stuffing", "data/anomalous_credential_stuffing.jsonl")
    generate_anomalous_file("exfiltration", "data/anomalous_exfiltration.jsonl")
    generate_anomalous_file("scanning", "data/anomalous_scanning.jsonl")
    
    print()
    print("✓ All log files generated successfully")
