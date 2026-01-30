class OWASP2025Rules:
    def load_owasp_2025_rules():
        return [
            {
                "id": "WAF-001",
                "name": "IDOR / Privilege Escalation Attempt",
                "owasp": "A01:2025 - Broken Access Control",
                "type": "MALICIOUS",
                "pattern": r"(admin|root|superuser|/internal|/private)",
                "severity": "HIGH",
                "action": "BLOCK"
            },
            {
                "id": "WAF-002",
                "name": "Exposed Debug or Config Files",
                "owasp": "A02:2025 - Security Misconfiguration",
                "type": "MALICIOUS",
                "pattern": r"(\.env|\.git|config\.yml|debug=true)",
                "severity": "HIGH",
                "action": "BLOCK"
            },
            {
                "id": "WAF-003",
                "name": "Malicious Package Reference",
                "owasp": "A03:2025 - Software Supply Chain Failures",
                "type": "MALICIOUS",
                "pattern": r"(npm install .*@|pip install .*==)",
                "severity": "MEDIUM",
                "action": "BLOCK"
            },
            {
                "id": "WAF-004",
                "name": "Weak Crypto Usage",
                "owasp": "A04:2025 - Cryptographic Failures",
                "type": "MALICIOUS",
                "pattern": r"(md5|sha1|DES|RC4)",
                "severity": "MEDIUM",
                "action": "BLOCK"
            },
            {
                "id": "WAF-005",
                "name": "SQL Injection Attempt",
                "owasp": "A05:2025 - Injection",
                "type": "MALICIOUS",
                "pattern": r"(\bor\b|\band\b).*(=|LIKE)|(--|;)",
                "severity": "CRITICAL",
                "action": "BLOCK"
            },
            {
                "id": "WAF-006",
                "name": "Client-Side Trust Manipulation",
                "owasp": "A06:2025 - Insecure Design",
                "type": "MALICIOUS",
                "pattern": r"(isAdmin=true|role=admin)",
                "severity": "HIGH",
                "action": "BLOCK"
            },
            {
                "id": "WAF-007",
                "name": "Credential Stuffing Indicators",
                "owasp": "A07:2025 - Authentication Failures",
                "type": "MALICIOUS",
                "pattern": r"(password=123456|admin:admin)",
                "severity": "HIGH",
                "action": "BLOCK"
            },
            {
                "id": "WAF-008",
                "name": "Unsigned or Tampered Payload",
                "owasp": "A08:2025 - Software or Data Integrity Failures",
                "type": "MALICIOUS",
                "pattern": r"(signature=none|checksum=disabled)",
                "severity": "HIGH",
                "action": "BLOCK"
            },
            {
                "id": "WAF-009",
                "name": "Log Suppression Attempt",
                "owasp": "A09:2025 - Security Logging and Alerting Failures",
                "type": "MALICIOUS",
                "pattern": r"(disableLogging|log=false)",
                "severity": "MEDIUM",
                "action": "BLOCK"
            },
            {
                "id": "WAF-010",
                "name": "Stack Trace or Exception Leak",
                "owasp": "A10:2025 - Mishandling of Exceptional Conditions",
                "type": "MALICIOUS",
                "pattern": r"(Exception|Traceback|Stack trace)",
                "severity": "MEDIUM",
                "action": "BLOCK"
            }
        ]