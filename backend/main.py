"""
signaltrace - Backend API
Minimal FastAPI application for log analysis with hybrid anomaly detection
"""

import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

from urllib.parse import urlparse

import bcrypt
import jwt
from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import numpy as np
from sklearn.ensemble import IsolationForest

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET", "change-this-in-production")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "analyst@tenex.ai")
ADMIN_PASSWORD_HASH = bcrypt.hashpw(
    os.getenv("ADMIN_PASSWORD", "password123").encode(), 
    bcrypt.gensalt()
)

# FastAPI app
app = FastAPI(title="signaltrace")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth
security = HTTPBearer()


# Models
class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    token: str
    email: str


class AnalysisResponse(BaseModel):
    filename: str
    total_logs: int
    anomaly_count: int
    risk_level: str
    summary: str
    detection_breakdown: Dict[str, Any]
    time_range: Dict[str, Any]
    peak_activity: Optional[Dict[str, Any]]
    timeline: List[Dict]
    anomalies: List[Dict]
    logs: List[Dict]


# Auth helpers
def create_token(email: str) -> str:
    """Create JWT token"""
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify JWT token"""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload["email"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# Routes
@app.post("/api/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    """Simple JWT login"""
    if req.email != ADMIN_EMAIL:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    if not bcrypt.checkpw(req.password.encode(), ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    token = create_token(req.email)
    return LoginResponse(token=token, email=req.email)


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_logs(
    file: UploadFile = File(...),
    email: str = Depends(verify_token)
):
    """
    Upload and analyze log file
    Returns hybrid detection results (rule-based + IsolationForest)
    """
    
    # Read and parse logs
    content = await file.read()
    logs = []
    
    for line in content.decode().strip().split('\n'):
        if line:
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    
    if not logs:
        raise HTTPException(status_code=400, detail="No valid logs found")
    
    # Run detection
    results = detect_anomalies(logs)
    results["filename"] = file.filename
    
    return results


# Detection logic
def extract_hostname(url: str) -> str:
    """Extract hostname from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except:
        return url


def extract_features_per_ip(logs: List[Dict]) -> Dict[str, Dict]:
    """
    Extract behavioral features per client IP
    
    Features (for IsolationForest):
    - requests_per_minute_peak: max requests in any 1-minute window
    - deny_rate: proportion of DENY actions
    - total_bytes_transferred: sum of responsesize
    - unique_hosts_count: distinct hostnames accessed
    - off_hours_request_ratio: proportion of requests 00:00-05:00 UTC
    """
    
    from collections import defaultdict
    
    ip_data = defaultdict(lambda: {
        'requests': [],
        'timestamps': [],
        'hosts': set(),
        'denies': 0,
        'total_bytes': 0,
        'off_hours': 0
    })
    
    # Aggregate per IP
    for log in logs:
        ip = log.get('clientip', '')
        if not ip:
            continue
        
        data = ip_data[ip]
        data['requests'].append(log)
        
        # Parse timestamp
        try:
            ts = datetime.fromisoformat(log['time'].replace('Z', '+00:00'))
            data['timestamps'].append(ts)
            
            # Off-hours check (00:00-05:00 UTC)
            if 0 <= ts.hour < 5:
                data['off_hours'] += 1
        except:
            pass
        
        # Host
        hostname = extract_hostname(log.get('url', ''))
        if hostname:
            data['hosts'].add(hostname)
        
        # Denies
        if log.get('action') == 'DENY':
            data['denies'] += 1
        
        # Bytes
        data['total_bytes'] += log.get('responsesize', 0)
    
    # Calculate features
    features = {}
    for ip, data in ip_data.items():
        req_count = len(data['requests'])
        
        # Peak rate (max in any 1-min window)
        peak_rate = calc_peak_rate(data['timestamps'])
        
        # Deny rate
        deny_rate = data['denies'] / req_count if req_count > 0 else 0
        
        # Off-hours ratio
        off_hours_ratio = data['off_hours'] / req_count if req_count > 0 else 0
        
        features[ip] = {
            'requests_per_minute_peak': peak_rate,
            'deny_rate': deny_rate,
            'total_bytes_transferred': data['total_bytes'],
            'unique_hosts_count': len(data['hosts']),
            'off_hours_request_ratio': off_hours_ratio,
            'request_count': req_count,
            'timestamps': data['timestamps']
        }
    
    return features


def calc_peak_rate(timestamps: List[datetime]) -> float:
    """Calculate maximum requests in any 1-minute window"""
    if len(timestamps) < 2:
        return len(timestamps)
    
    timestamps = sorted(timestamps)
    max_rate = 0
    
    for i, ts in enumerate(timestamps):
        window_end = ts + timedelta(minutes=1)
        count = sum(1 for t in timestamps[i:] if t <= window_end)
        max_rate = max(max_rate, count)
    
    return max_rate


def apply_deterministic_rules(ip: str, features: Dict) -> List[str]:
    """
    Apply deterministic rule thresholds
    Returns list of triggered rule names
    """
    triggered = []
    
    # High Burst
    if features['requests_per_minute_peak'] >= 100:
        triggered.append("High Burst")
    
    # High Deny Rate
    if features['deny_rate'] >= 0.6:
        triggered.append("High Deny Rate")
    
    # Extreme Data Transfer
    if features['total_bytes_transferred'] >= 50_000_000:
        triggered.append("Extreme Data Transfer")
    
    # High Unique Hosts
    if features['unique_hosts_count'] >= 20:
        triggered.append("High Unique Hosts")
    
    # High Off-Hours Activity
    if features['off_hours_request_ratio'] >= 0.7:
        triggered.append("High Off-Hours Activity")
    
    return triggered


def assign_severity(triggered_rules: List[str], isolation_score: float) -> str:
    """
    Assign severity based on triggered rules
    
    Critical: (High Burst AND High Deny Rate) OR (Extreme Data Transfer AND High Off-Hours)
    High: Any two rule triggers
    Medium: Any single rule trigger OR isolation_score >= 0.85
    Low: isolation_score between 0.75 and 0.85
    """
    
    if not triggered_rules and isolation_score < 0.75:
        return None  # Not anomalous

    # Critical conditions
    if ("High Burst" in triggered_rules and "High Deny Rate" in triggered_rules):
        return "Critical"
    if ("Extreme Data Transfer" in triggered_rules and "High Off-Hours Activity" in triggered_rules):
        return "Critical"
    
    # High: any 2 rules
    if len(triggered_rules) >= 2:
        return "High"
    
    # Medium: 1 rule or very high IF score
    if len(triggered_rules) >= 1:
        return "Medium"
    if isolation_score >= 0.85:
        return "Medium"

    # Low: high IF score
    if isolation_score >= 0.75:
        return "Low"
    
    return None


def calculate_confidence(triggered_rules: List[str], isolation_score: float) -> float:
    """
    Calculate confidence score (0-1)
    Simple weighted combination of rule triggers + normalized IF score
    """
    rule_weight = 0.7
    if_weight = 0.3
    
    # Total possible rules
    total_rules = 5  # High Burst, High Deny Rate, Extreme Data Transfer, High Unique Hosts, High Off-Hours
    
    # Treat rule triggers as binary evidence:
    # any triggered rule = strong deterministic signal (1.0), none = 0.0 
    rule_score = 1.0 if triggered_rules else 0.0
    
    # IF contribution (already 0-1)
    if_contribution = isolation_score
    
    confidence = (rule_weight * rule_score) + (if_weight * if_contribution)
    return round(confidence, 2)


def detect_anomalies(logs: List[Dict]) -> Dict:
    """
    Main detection pipeline
    Combines rule-based + IsolationForest detection
    """
    
    # Extract per-IP features
    ip_features = extract_features_per_ip(logs)
    
    if len(ip_features) < 20:
        # Not enough IPs for meaningful IsolationForest analysis
        # Fall back to rule-based detection only
        
        rule_anomalies = []
        anomalous_ips = set()
        
        for ip, features in ip_features.items():
            # Apply deterministic rules
            triggered_rules = apply_deterministic_rules(ip, features)
            
            if not triggered_rules:
                continue  # Not anomalous
            
            # Assign severity based on rules only
            if ("High Burst" in triggered_rules and "High Deny Rate" in triggered_rules):
                severity = "Critical"
            elif ("Extreme Data Transfer" in triggered_rules and "High Off-Hours Activity" in triggered_rules):
                severity = "Critical"
            elif len(triggered_rules) >= 2:
                severity = "High"
            else:
                severity = "Medium"
                
                
            #In rule-only mode (<20 IPs), confidence is binary.
            # Any triggered rule represents a high-precision deterministic signal,
            # so we assign full confidence rather than scaling by rule count.
            confidence = 1.0
            
            rule_anomalies.append({
                "clientip": ip,
                "severity": severity,
                "confidence": confidence,
                "detection_method": "Rule-based",
                "triggered_rules": triggered_rules,
                "features": {
                    "requests_per_minute_peak": round(features['requests_per_minute_peak'], 1),
                    "deny_rate": round(features['deny_rate'], 2),
                    "total_bytes_transferred": features['total_bytes_transferred'],
                    "unique_hosts_count": features['unique_hosts_count'],
                    "off_hours_request_ratio": round(features['off_hours_request_ratio'], 2)
                },
                "isolation_score": 0,
                "explanation": f"Triggered rules: {', '.join(triggered_rules)}",
                "first_seen": min(features['timestamps']).isoformat() if features['timestamps'] else None,
                "request_count": features['request_count']
            })
            
            anomalous_ips.add(ip)
        
        # Generate summary
        summary = generate_summary(len(logs), len(ip_features), rule_anomalies)
        risk_level = calculate_risk_level(rule_anomalies)
        timeline = build_timeline(rule_anomalies)
        
        return {
            "total_logs": len(logs),
            "anomaly_count": len(rule_anomalies),
            "risk_level": risk_level,
            "summary": summary if rule_anomalies else f"Analyzed {len(logs)} logs from {len(ip_features)} IPs. No anomalies detected. All traffic appears normal.",
            "detection_breakdown": {
                "rule_based": len(rule_anomalies),
                "statistical": 0,
                "hybrid": 0,
                "total": len(rule_anomalies),
                "note": f"Statistical analysis skipped (dataset has {len(ip_features)} IPs, minimum 20 required)"  # ADD THIS LINE
            },
            "time_range": get_time_range(logs),
            "peak_activity": get_peak_activity(logs),
            "timeline": timeline,
            "anomalies": rule_anomalies,
            "logs": prepare_log_table(logs, anomalous_ips)
        }
    
    # If we reach here, we have ≥20 IPs - use full hybrid detection
    
    # Prepare feature matrix for IsolationForest
    ips = list(ip_features.keys())
    X = np.array([[
        ip_features[ip]['requests_per_minute_peak'],
        ip_features[ip]['deny_rate'],
        ip_features[ip]['total_bytes_transferred'],
        ip_features[ip]['unique_hosts_count'],
        ip_features[ip]['off_hours_request_ratio']
    ] for ip in ips])
    
    # Fit IsolationForest
    iso_forest = IsolationForest(contamination=0.03, random_state=42)
    predictions = iso_forest.fit_predict(X)
    scores = iso_forest.score_samples(X)
    
    # Normalize scores to 0-1 (more negative = more anomalous)
    min_score = scores.min()
    max_score = scores.max()
    if max_score - min_score > 0:
        normalized_scores = (max_score - scores) / (max_score - min_score)
    else:
        normalized_scores = np.zeros(len(scores))
    
    # Detect anomalies
    anomalies = []
    anomalous_ips = set()
    rule_based_count = 0
    statistical_count = 0
    hybrid_count = 0
    
    for i, ip in enumerate(ips):
        features = ip_features[ip]
        isolation_score = normalized_scores[i]
        
        # Apply rules
        triggered_rules = apply_deterministic_rules(ip, features)
        
        # Assign severity
        severity = assign_severity(triggered_rules, isolation_score)
        
        if not severity:
            continue  # Not anomalous
        
        # Calculate confidence
        confidence = calculate_confidence(triggered_rules, isolation_score)
        
        # Determine detection method
        if triggered_rules and isolation_score >= 0.75:
            method = "Hybrid"
            hybrid_count += 1
        elif triggered_rules:
            method = "Rule-based"
            rule_based_count += 1
        else:
            method = "Statistical"
            statistical_count += 1
        
        # Build explanation
        explanation_parts = []
        if triggered_rules:
            explanation_parts.append(f"Triggered rules: {', '.join(triggered_rules)}")
        if isolation_score >= 0.75:
            explanation_parts.append(f"Statistical anomaly score: {isolation_score:.2f}")
        
        explanation = ". ".join(explanation_parts)
        
        # Create anomaly record
        anomalies.append({
            "clientip": ip,
            "severity": severity,
            "confidence": confidence,
            "detection_method": method,
            "triggered_rules": triggered_rules,
            "features": {
                "requests_per_minute_peak": round(features['requests_per_minute_peak'], 1),
                "deny_rate": round(features['deny_rate'], 2),
                "total_bytes_transferred": features['total_bytes_transferred'],
                "unique_hosts_count": features['unique_hosts_count'],
                "off_hours_request_ratio": round(features['off_hours_request_ratio'], 2)
            },
            "isolation_score": round(isolation_score, 2),
            "explanation": explanation,
            "first_seen": min(features['timestamps']).isoformat() if features['timestamps'] else None,
            "request_count": features['request_count']
        })
        
        anomalous_ips.add(ip)
    
    # Sort by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    anomalies.sort(key=lambda x: (severity_order[x['severity']], -x['confidence']))
    
    # Calculate risk level
    risk_level = calculate_risk_level(anomalies)
    
    # Generate summary
    summary = generate_summary(len(logs), len(ip_features), anomalies)
    
    # Build timeline
    timeline = build_timeline(anomalies)
    
    # Detection breakdown
    detection_breakdown = {
        "rule_based": rule_based_count,
        "statistical": statistical_count,
        "hybrid": hybrid_count,
        "total": len(anomalies)
    }
    
    return {
        "total_logs": len(logs),
        "anomaly_count": len(anomalies),
        "risk_level": risk_level,
        "summary": summary,
        "detection_breakdown": detection_breakdown,
        "time_range": get_time_range(logs),
        "peak_activity": get_peak_activity(logs),
        "timeline": timeline,
        "anomalies": anomalies,
        "logs": prepare_log_table(logs, anomalous_ips)
    }


def calculate_risk_level(anomalies: List[Dict]) -> str:
    """
    Derive risk level from severity counts
    
    High Risk: ≥1 Critical OR ≥1 High
    Medium Risk: ≥1 Medium OR multiple Low
    Low Risk: Only Low anomalies
    """
    if not anomalies:
        return "Low"
    
    critical_count = sum(1 for a in anomalies if a['severity'] == 'Critical')
    high_count = sum(1 for a in anomalies if a['severity'] == 'High')
    medium_count = sum(1 for a in anomalies if a['severity'] == 'Medium')
    
    # High risk: any Critical or High severity
    if critical_count >= 1 or high_count >= 1:
        return "High"
    
    # Medium risk: any Medium severity or multiple Low
    if medium_count >= 1 or len(anomalies) >= 3:
        return "Medium"
    
    # Low risk: only Low severity anomalies
    return "Low"


def generate_summary(total_logs: int, total_ips: int, anomalies: List[Dict]) -> str:
    """Generate deterministic summary from detection results"""
    if not anomalies:
        return f"Analyzed {total_logs} logs from {total_ips} IPs. No significant anomalies detected. All traffic appears normal."
    
    # Group by severity
    critical = [a for a in anomalies if a['severity'] == 'Critical']
    high = [a for a in anomalies if a['severity'] == 'High']
    medium = [a for a in anomalies if a['severity'] == 'Medium']
    low = [a for a in anomalies if a['severity'] == 'Low']
    
    summary_parts = [f"Analyzed {total_logs} logs from {total_ips} IPs."]
    
    if critical:
        ips = ', '.join([a['clientip'] for a in critical[:3]])
        summary_parts.append(f"CRITICAL: {len(critical)} IP(s) showing severe attack patterns ({ips}).")
    
    if high:
        ips = ', '.join([a['clientip'] for a in high[:3]])
        summary_parts.append(f"HIGH: {len(high)} IP(s) with suspicious behavior ({ips}).")
    
    if medium:
        ips = ', '.join([a['clientip'] for a in medium[:3]])
        summary_parts.append(f"MEDIUM: {len(medium)} IP(s) with unusual activity ({ips}).")
    
    # Add recommendation based on severity
    if critical or high:
        summary_parts.append("Immediate investigation recommended.")
    elif medium:
        summary_parts.append("Review recommended.")
    elif low:
        summary_parts.append(f"LOW: {len(low)} IP(s) with minor statistical anomalies. Monitor for patterns.")
    
    return " ".join(summary_parts)


def build_timeline(anomalies: List[Dict]) -> List[Dict]:
    """Build chronological timeline of anomalies"""
    timeline = []
    for anomaly in anomalies:
        if anomaly.get('first_seen'):
            timeline.append({
                "timestamp": anomaly['first_seen'],
                "clientip": anomaly['clientip'],
                "detection_type": ', '.join(anomaly['triggered_rules']) if anomaly['triggered_rules'] else "Statistical Anomaly",
                "severity": anomaly['severity']
            })
    
    timeline.sort(key=lambda x: x['timestamp'])
    return timeline


def get_time_range(logs: List[Dict]) -> Dict[str, str]:
    """Get time range from logs"""
    timestamps = []
    for log in logs:
        try:
            ts = datetime.fromisoformat(log['time'].replace('Z', '+00:00'))
            timestamps.append(ts)
        except:
            pass
    
    if not timestamps:
        return {"start": "", "end": "", "duration_hours": 0}
    
    start = min(timestamps)
    end = max(timestamps)
    duration = (end - start).total_seconds() / 3600
    
    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "duration_hours": round(duration, 1)
    }


def get_peak_activity(logs: List[Dict]) -> Optional[Dict]:
    """Find peak activity window"""
    from collections import Counter
    
    hour_counts = Counter()
    for log in logs:
        try:
            ts = datetime.fromisoformat(log['time'].replace('Z', '+00:00'))
            hour_counts[ts.hour] += 1
        except:
            pass
    
    if not hour_counts:
        return None
    
    peak_hour, peak_count = hour_counts.most_common(1)[0]
    return {
        "hour": peak_hour,
        "event_count": peak_count
    }


def prepare_log_table(logs: List[Dict], anomalous_ips: set) -> List[Dict]:
    """Prepare log table for frontend"""
    table_logs = []
    for log in logs:
        ip = log.get('clientip', '')
        table_logs.append({
            "time": log.get('time', ''),
            "clientip": ip,
            "host": extract_hostname(log.get('url', '')),
            "action": log.get('action', ''),
            "responsecode": log.get('responsecode', 0),
            "is_anomalous": ip in anomalous_ips
        })
    return table_logs


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
