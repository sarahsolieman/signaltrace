# signaltrace

A minimal log analysis and anomaly detection system combining deterministic rule-based detection with unsupervised machine learning (IsolationForest) for behavioral anomaly scoring. Designed for SOC analysts to quickly identify security threats in web proxy logs.

**Problem:** Security teams need to identify attacks in high-volume log data without labeled training datasets. Traditional signature-based detection misses novel threats; pure statistical methods generate false positives on normal variance.

**Solution:** Hybrid detection using explicit attack patterns (rules) for precision and IsolationForest for coverage of unknown behavioral anomalies.

---

## Quick Start

```bash
docker compose up --build
```

- **URL:** http://localhost:3000
- **Login:** analyst@tenex.ai / password123
- **Test:** Upload any `.jsonl` file from `data/` directory

---

## Architecture

**Backend:**
- FastAPI (Python)
- JWT authentication
- Log parsing (regex)
- Per-IP feature aggregation
- Deterministic rule engine
- IsolationForest statistical model
- Stateless processing

**Frontend:**
- Next.js 14 (TypeScript)
- 3 pages: Login, Upload, Results
- 4 result sections: Summary, Timeline, Anomaly Cards, Log Table

**Deployment:**
- Docker Compose
- No database (in-memory processing)
- No external dependencies

---

## Project Structure

```
signaltrace/
├── backend/
│   ├── main.py              # FastAPI + detection logic
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/app/
│   │   ├── login/page.tsx
│   │   ├── upload/page.tsx
│   │   └── results/page.tsx
│   ├── package.json
│   └── Dockerfile
├── data/
│   ├── baseline_small.jsonl
│   ├── baseline_medium.jsonl
│   ├── baseline_large.jsonl
│   ├── anomalous_credential_stuffing.jsonl
│   ├── anomalous_exfiltration.jsonl
│   └── anomalous_scanning.jsonl
├── generate_logs.py
├── docker-compose.yml
└── README.md
```

---

## API Contract

### POST `/api/auth/login`

**Request:**
```json
{
  "email": "analyst@tenex.ai",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJ...",
  "email": "analyst@tenex.ai"
}
```

### POST `/api/analyze`

**Headers:** `Authorization: Bearer <token>`  
**Body:** FormData with `file` field (JSONL)

**Response:**
```json
{
  "total_logs": 1000,
  "anomaly_count": 1,
  "risk_level": "High",
  "summary": "Analysis identified...",
  "detection_breakdown": {
    "rule_based": 1,
    "statistical": 0,
    "hybrid": 0,
    "total": 1
  },
  "anomalies": [...],
  "timeline": [...],
  "logs": [...]
}
```

---

## Log Format Specification

Logs must be **JSONL** (one JSON object per line):

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

**Required Constraints:**
- `time`: ISO8601 UTC with Z suffix
- `action`: Exactly "ALLOW" or "DENY"
- `url`: Full URL including scheme and hostname

---

## Sample Data

| File | Description | Expected Behavior |
|------|-------------|-------------------|
| `baseline_small.jsonl` | 1,000 normal events | 0 anomalies, Low risk |
| `baseline_medium.jsonl` | 3,000 normal events | 0 anomalies, Low risk |
| `baseline_large.jsonl` | 5,000 normal events | 0 anomalies, Low risk |
| `anomalous_credential_stuffing.jsonl` | Brute force attack | 1 Critical anomaly, High risk |
| `anomalous_exfiltration.jsonl` | Data theft | 1 Critical anomaly, High risk |
| `anomalous_scanning.jsonl` | Network reconnaissance | 1 High anomaly, High risk |

**Attack Scenarios:**

**Credential Stuffing** (IP: 203.0.113.45)  
150 requests/minute, 90% deny rate → Triggers: High Burst + High Deny Rate

**Data Exfiltration** (IP: 192.168.1.150)  
75 MB transferred during off-hours (2-4 AM) → Triggers: Extreme Data Transfer + High Off-Hours Activity

**Scanning** (IP: 198.51.100.89)  
30 unique hosts probed, 66% denied → Triggers: High Unique Hosts + High Deny Rate

---

## Detection System

### 8.1 Behavioral Feature Extraction

Five features extracted per client IP:

1. **requests_per_minute_peak** - Maximum requests in any 1-minute window
2. **deny_rate** - Proportion of DENY actions (0-1)
3. **total_bytes_transferred** - Sum of responsesize field
4. **unique_hosts_count** - Distinct hostnames extracted from URLs
5. **off_hours_request_ratio** - Proportion of requests 00:00-05:00 UTC

### 8.2 Deterministic Rule Engine

Explicit threshold-based detection:

| Rule | Feature Used | Threshold |
|------|--------------|-----------|
| High Burst | requests_per_minute_peak | ≥ 100 |
| High Deny Rate | deny_rate | ≥ 0.6 |
| Extreme Data Transfer | total_bytes_transferred | ≥ 50 MB |
| High Unique Hosts | unique_hosts_count | ≥ 20 |
| High Off-Hours Activity | off_hours_request_ratio | ≥ 0.7 |

**Purpose:** High-precision detection of known attack patterns.

### 8.3 IsolationForest Statistical Model

**Input:** Same 5 features (not thresholds)  
**Model:** IsolationForest with contamination=0.03  
**Output:** Normalized anomaly score (0-1)  
**Minimum Dataset:** ≥20 unique IPs required

**Key Properties:**
- Does not use thresholds
- Does not explain anomalies
- Identifies behavioral outliers statistically
- Skipped if <20 IPs (falls back to rules only)

**Calibration:**
- `contamination=0.03`: Expects 3% of IPs to be anomalous (realistic for enterprise traffic)
- `threshold=0.75`: High threshold for statistical-only detections (reduces false positives)
- `minimum=20 IPs`: Prevents false positives from normal variance in small samples

**Purpose:** Coverage for novel or unknown threats not matching rule patterns.

### 8.4 How They Work Together (Hybrid Logic)

**Detection Pipeline:**

1. **Feature Extraction** - Compute 5 behavioral features per IP
2. **Rule Evaluation** - Check if any of 5 thresholds exceeded
3. **IsolationForest Scoring** - Compute statistical anomaly score (if ≥20 IPs)
4. **Severity Assignment** - Classify based on triggered rules + IF score
5. **Confidence Calculation** - Weighted combination: `0.7 × rule_score + 0.3 × IF_score`
6. **Risk Level Derivation** - File-level aggregation from all anomaly severities

**Detection Method Classification:**
- **Rule-based:** Rules triggered, IF score <0.75
- **Statistical:** IF score ≥0.75, no rules triggered
- **Hybrid:** Both rules triggered AND IF score ≥0.75 (strongest signal)

---

## Severity vs Confidence vs Risk

Three distinct abstraction layers:

**Severity** (Per-IP Classification):
- Critical: (High Burst AND High Deny Rate) OR (Extreme Transfer AND Off-Hours)
- High: Any 2 rule triggers
- Medium: 1 rule trigger OR IF score ≥0.85
- Low: IF score 0.75-0.85, no rules

**Confidence** (Signal Strength Score):
```
confidence = (0.7 × rule_score) + (0.3 × IF_score)
where rule_score = triggered_rules / 5
```
Range: 0-1 (represents detection signal strength, not probability of maliciousness)

**Risk Level** (File-Level Aggregation):
- High Risk: ≥1 Critical OR ≥1 High anomaly
- Medium Risk: ≥1 Medium OR ≥3 Low anomalies
- Low Risk: ≤2 Low anomalies or none

**Conceptual Flow:**
```
Features → Rules/Model → Severity → Confidence → File Risk
```

**Important Distinction:**
- Severity depends on **which** rules trigger (specific attack patterns)
- Confidence depends on **how many** signals fire (total evidence strength)

---

## Design Decisions

**Why IsolationForest?**  
No labeled training data required (unsupervised), established in fraud/security detection, fast inference, interpretable via feature contributions.

**Why Hybrid Approach?**  
Rules provide precision for known attacks; IsolationForest provides coverage for novel threats. Combining both reduces false negatives while maintaining explainability.

---

**Regenerate sample logs:** `python3 generate_logs.py`  

 





