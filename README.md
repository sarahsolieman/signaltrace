# signaltrace

A minimal log analysis and anomaly detection system combining deterministic rule-based detection with unsupervised machine learning (IsolationForest) for behavioral anomaly scoring. Designed for SOC analysts to quickly identify security threats in web proxy logs.

**Problem:** Security teams need to identify attacks in high-volume log data without labeled training datasets. Traditional signature-based detection misses novel threats; pure statistical methods generate false positives on normal variance.

**Solution:** Hybrid detection using explicit attack patterns (rules) for precision and IsolationForest for coverage of unknown behavioral anomalies.

---

## Quick Start

### Prerequisites
- Docker Desktop installed and running  
- Git (if cloning from a repository)

### Run Locally

```bash
# 1. Unzip and navigate into the project directory
cd signaltrace

# 2. Build and start the application
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

### Attack Scenarios

**Credential Stuffing** (IP: 203.0.113.45)  
150 requests/minute, 90% deny rate → Triggers: High Burst + High Deny Rate  

**Data Exfiltration** (IP: 192.168.1.150)  
75 MB transferred during off-hours (2–4 AM) → Triggers: Extreme Data Transfer + High Off-Hours Activity  

**Scanning** (IP: 198.51.100.89)  
30 unique hosts probed, 66% denied → Triggers: High Unique Hosts + High Deny Rate  

---

## Detection System

### Behavioral Feature Extraction

Five features extracted per client IP:

1. **requests_per_minute_peak** — Maximum requests in any 1-minute window  
2. **deny_rate** — Proportion of DENY actions (0–1)  
3. **total_bytes_transferred** — Sum of `responsesize` field  
4. **unique_hosts_count** — Distinct hostnames extracted from URLs  
5. **off_hours_request_ratio** — Proportion of requests 00:00–05:00 UTC  

---

### Deterministic Rule Engine

| Rule | Feature Used | Threshold |
|------|--------------|-----------|
| High Burst | requests_per_minute_peak | ≥ 100 |
| High Deny Rate | deny_rate | ≥ 0.6 |
| Extreme Data Transfer | total_bytes_transferred | ≥ 50 MB |
| High Unique Hosts | unique_hosts_count | ≥ 20 |
| High Off-Hours Activity | off_hours_request_ratio | ≥ 0.7 |

Purpose: High-precision detection of known attack patterns.

---

### IsolationForest Statistical Model

- **Input:** Same 5 features (not thresholds)  
- **Model:** IsolationForest with contamination=0.03  
- **Output:** Normalized anomaly score (0–1)  
- **Minimum Dataset:** ≥20 unique IPs required  

Calibration:
- `contamination=0.03` reflects realistic enterprise anomaly rates  
- `threshold=0.75` reduces statistical false positives  
- `<20 IPs` → statistical model skipped  

Purpose: Coverage for novel or unknown threats not matching rule patterns.

---

## Hybrid Logic

Detection Pipeline:

1. Feature Extraction  
2. Rule Evaluation  
3. IsolationForest Scoring (if ≥20 IPs)  
4. Severity Assignment  
5. Confidence Calculation  
6. Risk Level Derivation  

Detection Method Classification:
- Rule-based  
- Statistical  
- Hybrid  

---

## Severity vs Confidence vs Risk

### Severity (Per-IP)

- Critical: (High Burst AND High Deny Rate) OR (Extreme Transfer AND Off-Hours)  
- High: Any 2 rule triggers  
- Medium: 1 rule trigger OR IF score ≥0.85  
- Low: IF score 0.75–0.85  

---

### Confidence (Signal Strength Score)

**Rule-Only Mode** (dataset < 20 unique IPs):

```python
confidence = 1.0
```

**Hybrid Mode** (dataset ≥ 20 unique IPs):

```python
confidence = (0.7 * rule_score) + (0.3 * IF_score)
where rule_score = 1.0 if any rules triggered, else 0.0
```

Range: 0–1 (represents detection signal strength, not probability of maliciousness)

---

### Risk Level (File-Level)

- High Risk: ≥1 Critical OR ≥1 High anomaly  
- Medium Risk: ≥1 Medium OR ≥3 Low anomalies  
- Low Risk: ≤2 Low anomalies or none  

Conceptual Flow:

```
Features → Rules/Model → Severity → Confidence → File Risk
```

Important Distinction:
- Severity depends on **which** rules trigger  
- Confidence reflects signal strength — not probability  

---

## Design Decisions

**Why IsolationForest?**  
Unsupervised, no labeled data required, fast inference, widely used in fraud/security.

**Why Hybrid?**  
Rules provide precision. IsolationForest provides coverage. Together they reduce false negatives while maintaining explainability.

---

## Regenerate Sample Logs

```bash
python3 generate_logs.py
```

 





