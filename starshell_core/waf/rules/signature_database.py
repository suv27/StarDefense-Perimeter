# starshell_core/waf/rules/signature_database.py

class SignatureDB:
    @staticmethod
    def load_owasp_2025_rules():
        rules = [
            {
                "id": "WAF-001",
                "name": "Broken Access Control",
                "category": "A01:2025",
                "pattern": r"(?i)(\.\.[/\\]|/etc/(passwd|shadow)|/(root|admin|config|internal|private)\b|htaccess|htpasswd)",
                "severity": "HIGH",
                "targets": ["path", "body", "headers"],
                "description": "Detected attempts to access sensitive system files or restricted administrative directories.",
                "mitigation": "Enforce strict path validation and implement a 'Least Privilege' access model."
            },
            {
                "id": "WAF-002",
                "name": "Cryptographic Failures",
                "category": "A02:2025",
                "pattern": r"(?i)\b(md5|sha1|rc4|des)\b",
                "severity": "HIGH",
                "targets": ["body", "query_string"],
                "description": "Detection of deprecated or weak cryptographic algorithms in the request payload.",
                "mitigation": "Upgrade to modern standards like AES-256 or SHA-256/3."
            },
            {
                "id": "WAF-003",
                "name": "Injection",
                "category": "A03:2025",
                "pattern": r"(?i)(' OR 1=1|--|;|UNION SELECT|DROP TABLE|SLEEP\()",
                "severity": "CRITICAL",
                "targets": ["body", "query_string"],
                "description": "Classic SQL Injection patterns found. Attempt to manipulate or bypass database queries.",
                "mitigation": "Use prepared statements, parameterized queries, and input sanitization libraries."
            },
            {
                "id": "WAF-004",
                "name": "Insecure Design",
                "category": "A04:2025",
                "pattern": r"(?i)[\"']?is_?admin[\"']?\s*[:=]\s*[\"']?(true|1|on)[\"']?",
                "severity": "HIGH",
                "targets": ["body"],
                "description": "Detected client-side attempts to force administrative privilege escalation.",
                "mitigation": "Perform all authorization checks server-side; never trust client-provided role flags."
            },
            {
                "id": "WAF-005",
                "name": "Security Misconfiguration",
                "category": "A05:2025",
                "pattern": r"(?i)(debug\s*[:=]\s*(\"on\"|true|1)|show_env)",
                "severity": "HIGH",
                "targets": ["body"],
                "description": "Attempt to enable debug modes or expose server environment variables.",
                "mitigation": "Disable debug features in production and use environment-specific configuration files."
            },
            {
                "id": "WAF-006",
                "name": "Vulnerable and Outdated Components",
                "category": "A06:2025",
                "pattern": r"(?i)(pip|npm|yarn)\s+install\s+[a-z0-9_-]+(@|\b)",
                "severity": "MEDIUM",
                "targets": ["body"],
                "description": "Detected package manager commands that could lead to dependency confusion or remote code execution.",
                "mitigation": "Use lock files, private registries, and automated dependency scanning (Snyk/Dependabot)."
            },
            {
                "id": "WAF-007",
                "name": "Identification and Authentication Failures",
                "category": "A07:2025",
                "pattern": r"(?i)[\"']?(user|pass|username|password)[\"']?\s*[:=]\s*[\"']?(admin|root|password)[\"']?",
                "severity": "HIGH",
                "targets": ["body"],
                "description": "Detected use of common default credentials or hardcoded administrative accounts.",
                "mitigation": "Enforce complex password policies and mandatory Multi-Factor Authentication (MFA)."
            },
            {
                "id": "WAF-008",
                "name": "Software and Data Integrity Failures",
                "category": "A08:2025",
                "pattern": r"(?i)(\.bin|\.update|sig\s*[:=]\s*none)",
                "severity": "HIGH",
                "targets": ["body"],
                "description": "Attempt to bypass digital signature verification or push unauthorized binary updates.",
                "mitigation": "Implement code signing and verify the integrity of all data/updates before processing."
            },
            {
                "id": "WAF-009",
                "name": "Security Logging and Monitoring Failures",
                "category": "A09:2025",
                "pattern": r"(?i)(delete|disable|remove|off|clear).{0,20}\.log",
                "severity": "MEDIUM",
                "targets": ["body"],
                "description": "Detected commands aimed at suppressing, clearing, or disabling security logs.",
                "mitigation": "Stream logs to a remote, write-once (WORM) storage system that attackers cannot modify."
            },
            {
                "id": "WAF-010",
                "name": "Server-Side Request Forgery (SSRF)",
                "category": "A10:2025",
                "pattern": r"(?i)(exception|traceback|stack\s*trace|127\.0\.0\.1|localhost|169\.254\.169\.254|internal\b)",
                "severity": "MEDIUM",
                "targets": ["body", "query_string"],
                "description": "Detected attempts to force the server to connect to internal resources or metadata services.",
                "mitigation": "Use an allow-list for external domains and disable access to cloud metadata endpoints (IMDSv2)."
            }
        ]
        return rules