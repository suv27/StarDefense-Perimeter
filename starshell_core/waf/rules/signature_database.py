# starshell_core/waf/rules/signature_database.py

class SignatureDB:
    @staticmethod
    def load_owasp_2025_rules():
        rules = [
            {
                "id": "WAF-001",
                "name": "Broken Access Control",
                "pattern": r"(?i)(\.\.[/\\]|/etc/(passwd|shadow)|/(root|admin|config|internal|private)\b|htaccess|htpasswd)",
                "severity": "HIGH",
                "targets": ["path", "body", "headers"]
            },
            {
                "id": "WAF-002",
                "name": "Cryptographic Failures",
                "pattern": r"(?i)\b(md5|sha1|rc4|des)\b",
                "severity": "HIGH",
                "targets": ["body", "query_string"]
            },
            {
                "id": "WAF-003",
                "name": "Injection",
                "pattern": r"(?i)(' OR 1=1|--|;|UNION SELECT|DROP TABLE|SLEEP\()",
                "severity": "CRITICAL",
                "targets": ["body", "query_string"]
            },
            {
                "id": "WAF-004",
                "name": "Insecure Design (Admin Manipulation)",
                "pattern": r"(?i)[\"']?is_?admin[\"']?\s*[:=]\s*[\"']?(true|1|on)[\"']?",
                "severity": "HIGH",
                "targets": ["body"]
            },
            {
                "id": "WAF-005",
                "name": "Security Misconfiguration",
                "pattern": r"(?i)(debug\s*[:=]\s*(\"on\"|true|1)|show_env)",
                "severity": "HIGH",
                "targets": ["body"]
            },
            {
                "id": "WAF-006",
                "name": "Vulnerable Components (Pip/NPM)",
                "pattern": r"(?i)(pip|npm|yarn)\s+install\s+[a-z0-9_-]+(@|\b)",
                "severity": "MEDIUM",
                "targets": ["body"]
            },
            {
                "id": "WAF-007",
                "name": "Identification Failure (Default Creds)",
                # This version specifically looks for the keys with or without quotes 
                # and handles the root/admin values in a JSON-string format.
                "pattern": r"(?i)[\"']?(user|pass|username|password)[\"']?\s*[:=]\s*[\"']?(admin|root|password)[\"']?",
                "severity": "HIGH",
                "targets": ["body"]
            },
            {
                "id": "WAF-008",
                "name": "Integrity Failure",
                "pattern": r"(?i)(\.bin|\.update|sig\s*[:=]\s*none)",
                "severity": "HIGH",
                "targets": ["body"]
            },
            {
                "id": "WAF-009",
                "name": "Logging Failure (Log Suppression)",
                "pattern": r"(?i)(delete|disable|remove|off|clear).{0,20}\.log",
                "severity": "MEDIUM",
                "targets": ["body"]
            },
            {
                "id": "WAF-010",
                "name": "Mishandling Exceptions / SSRF",
                "pattern": r"(?i)(exception|traceback|stack\s*trace|127\.0\.0\.1|localhost|169\.254\.169\.254|internal\b)",
                "severity": "MEDIUM",
                "targets": ["body", "query_string"]
            }
        ]
        return rules
