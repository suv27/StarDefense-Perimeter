# ⭐ StarDefense Perimeter

**StarDefense Perimeter** is a **Layer 7 Cloud Security / Perimeter Defense project** built with **Python and FastAPI**, designed to simulate how modern **Web Application Firewalls (WAF)** and **Bot Protection platforms** operate in real-world cloud environments.

This project focuses on **HTTP traffic inspection, security telemetry collection, attack detection, and policy enforcement** using a middleware-based architecture — similar in concept to **Cloudflare, Akamai, AWS WAF, and Shape Security**.

---

## The Entire “IDEA”

The goal of StarDefense is to **protect backend APIs by placing security controls in front of application logic**, not inside it.

### Request Flow (Current Implementation)

1. Frontend / Client sends an HTTP request
2. **Bot Protection Layer**
   - Extracts request telemetry
   - Identifies suspicious or automated behavior
3. **WAF Layer**
   - Normalizes the HTTP request
   - Inspects payloads against attack signatures
   - Classifies the request as **ALLOW / FLAG / BLOCK**
4. All activity is **logged**
5. If allowed → request reaches the FastAPI backend
6. Backend responds normally

---

## How to Run StarDefense Backend Server

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the FastAPI Server
```bash
fastapi dev star_defense/api/backend_apis.py
```

### 3. Open Fast API Documentation

Swagger UI in the Browser:
```bash
http://127.0.0.1:8000/docs
```

### Test with Curl / Postman
```bash
curl --location 'http://127.0.0.1:8000/login' \
--header 'User-Agent: Postman Runtime UA' \
--header 'Accept: application/json' \
--header 'Content-Type: application/json' \
--data '{
  "username": "testuser",
  "password": "testpassword"
}'
```
If the request is blocked, the server will return 403 Forbidden along with WAF or Bot Protection metadata.


### Project Structure
```bash
star_defense/
├── api/
│   └── backend_apis.py          # FastAPI application entry point
│
├── bot_protection/
│   ├── middleware.py            # Bot protection middleware
│   ├── telemetry.py             # Request telemetry extraction
│   ├── fingerprint.py           # (Planned) client fingerprinting
│   ├── scoring.py               # (Planned) bot scoring engine
│   ├── decision.py              # (Planned) enforcement logic
│   └── response.py              # (Planned) bot responses
│
├── waf/
│   └── engine.py                # WAF rule engine & evaluation
│   └── rules/
│       └── core_rules.py        # WAF legit test rules
│       └── owasp_2025_rules.py  # WAF TOP 10 OWASP rules
│
├── logparser/
│   └── log_analizer.py          # HTTP normalization and logging
│
├── tests/
│   ├── test_cases.py            # Legit and malicious test cases
│   └── run_security_tests.py    # Automated security tests
│
├── http_events_log.jsonl          # Structured HTTP security logs
├── requirements.txt
├── LICENSE
└── README.md
```

## 🛡️ Bot Protection Layer

### Purpose
Detect and mitigate **automated, abusive, or suspicious traffic** before it reaches the application logic or the WAF engine.

### Current Capabilities
- Extracts request telemetry, including:
  - Client IP address
  - HTTP method and request path
  - Request headers
  - User-Agent string
  - Request body size
  - Timestamp
- Attaches telemetry to `request.state` for downstream processing
- Establishes the foundation for **behavior-based bot detection**

### Planned Enhancements
- Bot scoring engine (risk-based scoring model)
- Client fingerprinting (header-based + behavioral signals)
- Client-side telemetry collection:
  - Mouse movement velocity
  - Typing cadence
  - Interaction timing
- Adaptive enforcement actions:
  - Allow
  - Challenge
  - Block

---

## 🔥 WAF – Attack Signature Detector

### Purpose
Inspect **Layer 7 HTTP traffic** for known and emerging web application attacks.

### How It Works
- Normalizes incoming HTTP requests using the `LogAnalyzer`
- Evaluates requests against signature-based detection rules
- Assigns:
  - Severity level
  - Confidence score
  - Enforcement action (`ALLOW`, `FLAG`, or `BLOCK`)

### OWASP Top 10: 2025 Coverage (In Progress)
- **A01** – Broken Access Control  
- **A02** – Security Misconfiguration  
- **A03** – Software Supply Chain Failures  
- **A04** – Cryptographic Failures  
- **A05** – Injection  
- **A06** – Insecure Design  
- **A07** – Authentication Failures  
- **A08** – Software and Data Integrity Failures  
- **A09** – Logging and Alerting Failures  
- **A10** – Mishandling of Exceptional Conditions  

---

## ⚙️ Backend Server APIs

Implemented using **FastAPI**.

### Current Endpoints
- `GET /status` – Health check endpoint
- `POST /login` – Protected test endpoint

### Planned Endpoints
- `POST /forgot-password`
- `POST /search-item`
- `GET /stats`

---

## 📊 Logging & Telemetry

- All HTTP requests are normalized and logged
- Security decisions are attached to requests for traceability
- Logs are written in structured format to support:
  - Security forensics
  - Dashboards and analytics
  - Future SIEM integrations

---

## 🧪 Automated Security Testing

The `tests/` directory contains:
- Legitimate traffic test cases
- OWASP-style attack simulations
- End-to-end validation of WAF decisions

This simulates **enterprise-grade security testing pipelines** commonly used in production environments.


## Architecture Diagram
```bash
         Client / Frontend
                |
                v
┌───────────────────────────────┐
│     Bot Protection Layer      │
│ - Telemetry Extraction        │
│ - Bot Signal Detection        │
└───────────────┬───────────────┘
                |
                v
┌───────────────────────────────┐
│        WAF Layer              │
│ - Request Normalization       │
│ - OWASP Signature Detection   │
│ - Allow / Block Decisions     │
└───────────────┬───────────────┘
                |
                v
┌───────────────────────────────┐
│      FastAPI Backend APIs     │
│ - /status                     │
│ - /login                      │
└───────────────┬───────────────┘
                |
                v
┌───────────────────────────────┐
│ Logs / Future Dashboard / SIEM│
└───────────────────────────────┘
```

## 🚀 Why This Project Matters

StarDefense demonstrates **real-world perimeter security engineering concepts**, including:

- Middleware-based Layer 7 traffic interception
- Clear separation of **detection**, **scoring**, and **enforcement**
- Explicit mapping to the **OWASP Top 10: 2025**
- Bot vs. human traffic analysis foundations
- Cloud-native security design patterns inspired by enterprise platforms

This is **not a toy WAF**.  
StarDefense is intentionally structured to resemble **production-grade security architectures** used in modern cloud environments.

---

## 🧭 Roadmap

Planned enhancements and future capabilities include:

- Advanced bot scoring and fingerprinting
- Behavioral telemetry analysis (human vs. automation)
- Rate limiting and abuse prevention engine
- Security dashboard for detections and trends
- Threat intelligence integration
- Cloud deployment (AWS / GCP)
- Machine learning–based anomaly detection

---

## ⚠️ Disclaimer

This project is intended **solely for educational and research purposes**.

It is **not designed to replace enterprise-grade security products** in production environments and should not be used as a standalone security control for live systems.
