# signaltrace

Minimal log analysis and anomaly detection system using hybrid detection (rule-based + IsolationForest).

## Quick Start

```bash
# Start the application
docker compose up --build

# Access at http://localhost:3000
# Login: analyst@tenex.ai / password123
```

## Architecture

**Backend**: FastAPI (Python)  
**Frontend**: Next.js (TypeScript)  
**Detection**: Hybrid (Deterministic Rules + IsolationForest)  
**Deployment**: Docker Compose

## Sample Data

Pre-generated log files in `data/`:

| File | Description | Expected Behavior |
|------|-------------|-------------------|
| `baseline_small.jsonl` | 1,000 normal events | 0 anomalies, Low risk |
| `baseline_medium.jsonl` | 3,000 normal events | 0 anomalies, Low risk |
| `baseline_large.jsonl` | 5,000 normal events | 0 anomalies, Low risk |
| `anomalous_credential_stuffing.jsonl` | Credential stuffing attack | Critical severity, High risk |
| `anomalous_exfiltration.jsonl` | Data exfiltration | Critical severity, High risk |
| `anomalous_scanning.jsonl` | Network scanning | High severity, Medium risk |

### Anomaly Scenarios

**Credential Stuffing** (`203.0.113.45`):
- 150 requests in 1 minute (>100 req/min threshold)
- 90% deny rate (>60% threshold)
- Triggers: "High Burst" + "High Deny Rate"
- Expected: Critical severity

**Data Exfiltration** (`192.168.1.150`):
- 75 MB total transfer (>50 MB threshold)
- 100% off-hours activity (>70% threshold)
- Triggers: "Extreme Data Transfer" + "High Off-Hours Activity"
- Expected: Critical severity

**Scanning** (`198.51.100.89`):
- 30 unique hosts accessed (>20 threshold)
- 66% deny rate (>60% threshold)
- Triggers: "High Unique Hosts" + "High Deny Rate"
- Expected: High severity

## Detection Methodology

### Feature Extraction (Per-IP)

Five behavioral features are extracted for each client IP:

1. **requests_per_minute_peak**: Maximum requests in any 1-minute window
2. **deny_rate**: Proportion of DENY actions (0-1)
3. **total_bytes_transferred**: Sum of `responsesize` field
4. **unique_hosts_count**: Distinct hostnames extracted from URLs
5. **off_hours_request_ratio**: Proportion of requests between 00:00-05:00 UTC

### Deterministic Rules

Explicit thresholds trigger high-confidence detections:

| Rule | Threshold | Confidence |
|------|-----------|------------|
| High Burst | requests_per_minute_peak ≥ 100 | High |
| High Deny Rate | deny_rate ≥ 0.6 | High |
| Extreme Data Transfer | total_bytes_transferred ≥ 50 MB | High |
| High Unique Hosts | unique_hosts_count ≥ 20 | High |
| High Off-Hours Activity | off_hours_request_ratio ≥ 0.7 | Medium |

### IsolationForest

Unsupervised statistical anomaly detection:

- **Input**: 5-dimensional feature vector per IP
- **Model**: IsolationForest with `contamination=0.1`
- **Output**: Anomaly score normalized to 0-1 range
- **Threshold**: Score ≥ 0.6 for flagging

IsolationForest identifies behavioral outliers that may not match known patterns.

### Severity Assignment

Severity is derived deterministically:

**Critical**:
- (High Burst AND High Deny Rate) OR
- (Extreme Data Transfer AND High Off-Hours Activity)

**High**:
- Any two rule triggers

**Medium**:
- Any single rule trigger OR
- IsolationForest score ≥ 0.75

**Low**:
- IsolationForest score between 0.6 and 0.75
- No rule triggers

### Confidence Score

Confidence (0-1) is calculated as:

```
confidence = (0.7 × rule_score) + (0.3 × isolation_score)

where:
  rule_score = min(triggered_rules_count / 3, 1.0)
  isolation_score = normalized IsolationForest anomaly score
```

This represents **signal strength**, not probability of maliciousness.

### Risk Level Derivation

Overall risk is determined from severity distribution:

- **High Risk**: ≥1 Critical anomaly OR ≥3 High anomalies
- **Medium Risk**: 1-2 High anomalies OR multiple Medium anomalies
- **Low Risk**: Only Medium/Low anomalies or none

## Frontend Layout

### 1. Summary Card
- File metadata (name, log count, time range)
- Anomaly count and risk level
- Detection breakdown (rule-based vs statistical)
- Deterministic summary text

### 2. Timeline
- Chronological list of anomaly events
- Timestamp, IP, detection type, severity
- Color-coded by severity

### 3. Anomaly Cards
- Per-IP anomaly details
- Severity, confidence score, detection method
- Triggered rules listed
- Feature values displayed
- Plain-text explanation

### 4. Raw Logs Table
- All log entries with key fields
- Filter: All / Anomalies Only
- Anomalous entries highlighted
- Shows: time, clientip, host, action, response code

## Log Format

Logs must be JSONL (one JSON object per line) with these fields:

```json
{
  "time": "2026-02-14T10:02:15Z",
  "clientip": "192.168.1.100",
  "user": "user@company.com",
  "method": "GET",
  "url": "https://example.com/path",
  "action": "ALLOW",
  "responsecode": 200,
  "requestsize": 512,
  "responsesize": 2048,
  "useragent": "Mozilla/5.0...",
  "category": "Business"
}
```

Required field constraints:
- `time`: ISO8601 UTC with Z suffix
- `action`: Exactly "ALLOW" or "DENY"
- `url`: Full URL with scheme and hostname

## API Endpoints

### POST `/api/auth/login`
Authenticate and receive JWT token.

**Request**:
```json
{
  "email": "analyst@tenex.ai",
  "password": "password123"
}
```

**Response**:
```json
{
  "token": "eyJ...",
  "email": "analyst@tenex.ai"
}
```

### POST `/api/analyze`
Upload and analyze log file.

**Headers**: `Authorization: Bearer <token>`  
**Body**: FormData with `file` field (JSONL)

**Response**: Full analysis object with anomalies, timeline, and logs

## Regenerating Sample Logs

```bash
python3 generate_logs.py
```

This creates all 6 sample files in `data/` directory with deterministic output (seeded random).


## Testing

Upload each anomalous file and verify:

1. **credential_stuffing.jsonl**:
   - 1 Critical anomaly (IP 203.0.113.45)
   - Triggered rules: High Burst, High Deny Rate
   - Confidence: ~0.75-0.85
   - Risk: High

2. **exfiltration.jsonl**:
   - 1 Critical anomaly (IP 192.168.1.150)
   - Triggered rules: Extreme Data Transfer, High Off-Hours Activity
   - Confidence: ~0.70-0.80
   - Risk: High

3. **scanning.jsonl**:
   - 1 High anomaly (IP 198.51.100.89)
   - Triggered rules: High Unique Hosts, High Deny Rate
   - Confidence: ~0.75-0.85
   - Risk: Medium

## Project Structure

```
signaltrace/
├── backend/
│   ├── main.py              # FastAPI app + detection logic
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/app/
│   │   ├── login/page.tsx   # Login page
│   │   ├── upload/page.tsx  # File upload page
│   │   └── results/page.tsx # Analysis results (4 sections)
│   ├── package.json
│   └── Dockerfile
├── data/
│   ├── baseline_small.jsonl
│   ├── baseline_medium.jsonl
│   ├── baseline_large.jsonl
│   ├── anomalous_credential_stuffing.jsonl
│   ├── anomalous_exfiltration.jsonl
│   └── anomalous_scanning.jsonl
├── generate_logs.py         # Synthetic log generator
├── docker-compose.yml
└── README.md
```

## Design Decisions

### Why IsolationForest?
- No labeled training data required (unsupervised)
- Well-suited for anomaly detection
- Established algorithm in security/fraud detection
- Fast training and inference
- Interpretable via feature contributions

### Why Hybrid Approach?
- **Rules**: High precision for known attack patterns
- **Statistical**: Coverage for novel or unknown threats
- **Combined**: Reduces false negatives while maintaining explainability

### Why No LLM for Summaries?
- Adds latency and API dependencies
- Deterministic summaries are reproducible
- Rule-based text generation is sufficient for structured findings
- Keeps implementation simple and testable

### Why No Database?
- Stateless processing is simpler
- In-memory analysis is fast enough for demo
- Production would add PostgreSQL for history/trends




