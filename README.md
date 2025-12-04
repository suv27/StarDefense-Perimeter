# StarDefense Perimeter
a Cloud Security Peronal Project that includes Cloud Security, WAF and BOT Protection


## The Entire "IDEA"
- Frontend traffic
- Captured by LogParser
- Sent to Attack Signature Detector
- Classifies as safe or malicious
- Logs everything
- If safe → forwarded to FastAPI backend
- Dashboard shows live logs + detections


## How to Run StarDefense Backend Server


## How to Execure The PreDefined Script


## Attack Signature Detector
- We will be creating a list of detecting signature, starting with just The OWASP Top 10:2025
    - A01:2025 - Broken Access Control
    - A02:2025 - Security Misconfiguration
    - A03:2025 - Software Supply Chain Failures
    - A04:2025 - Cryptographic Failures
    - A05:2025 - Injection
    - A06:2025 - Insecure Design
    - A07:2025 - Authentication Failures
    - A08:2025 - Software or Data Integrity Failures
    - A09:2025 - Logging & Alerting Failures
    - A10:2025 - Mishandling of Exceptional Conditions

## BackEnd Server APIs
- We will be defining all the APIs using the Python Framework FastApi. Below are the started APIs we will be implementing
    - /login
    - /forgot-pasword
    - /application-submit

## The LogParser - WAF Layer
- This later will essentially sit infront of the backend fastAPI Server, it purpose will be to intercept all of the traffic going into the Backend Server, and log it out, everything will be in monitoring mode for now and we will flag it if potentially it can be DENY / Block base on the signature provided by the Attack Signature Detector Feature. 

## FrontEnd


## Architecture Network Diagram
                                   ┌───────────────────────────────┐
                                   │        WEB FrontEnd App       │
                                   │(HTTP/s Layer 7 Traffic events)│
                                   │ - /login                      │
                                   │ - /forgot-password            │
                                   │ - /application-submit         │
                                   └───────────────┬───────────────┘
                                                   │
                                                   ▼
┌──────────────────────────────────────────────────┴───────────────────────────────────────────────────┐ 
|                                        StarDefense Perimeter                                         |
|  ┌──────────────────────────┐    ┌───────────────────────────────┐  ┌─────────────────────────────┐  |
|  │      LogParser Module    │    │   AttackSignatureDetector     │  │   Future: Bot Detector      │  |
|  │ (src/LogParser/)         │    │ (src/AttackSignatureDetector/)│  │ - unknown                   │  |
|  │ - Normalize requests     │ -> │ - Pattern matching (OWASP)    │  │                             │  |
|  │ - Extract ALL HTTP fields│    │ - Block/Allow Decisions       │  │                             │  |
|  | - Standardize Log format |    | - Keyword / regex signatures  |  |                             |  |
|  └──────────────────────────┘    └───────────────────────────────┘  └─────────────────────────────┘  |
|                                                                                                      |
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                                   │
                                                   ▼
                                    ┌───────────────────────────────┐
                                    │      FastAPI Backend APIs     │
                                    │ (src/APIs/backendApis.py)     │
                                    │ - /parse-logs                 │
                                    │ - /detect-attack              │
                                    │ - /stats                      │
                                    └───────────────┬───────────────┘
                                                    │ responses (JSON)
                                                    ▼
                                    ┌───────────────────────────────┐
                                    │  Client / FrontEnd Dashboard  │
                                    │ - Dashboard UI/UX FrontEnd    │
                                    │ - Export to Dashboard/SEIM    │
                                    │ - Bot Detection Modules       │
                                    └───────────────────────────────┘
