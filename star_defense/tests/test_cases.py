class TestCases:
    def load_test_cases():
        default_headers = {
            "Content-Type": "application/json;v=1",
            "User-Agent": "star_defense_test_agent/1.0"
        }
        return [
            # =====================
            # LEGITIMATE REQUESTS
            # =====================
            {
                "name": "Legit Login",
                "headers": default_headers,
                "payload": {"username": "starlyn", "password": "Password123!"},
                "expected": "ALLOW"
            },
            {
                "name": "Legit Forgot Password",
                "headers": default_headers,
                "payload": {"email": "user@example.com"},
                "expected": "ALLOW"
            },
            {
                "name": "Legit Application Submit",
                "headers": default_headers,
                "payload": {"first_name": "John", "last_name": "Doe"},
                "expected": "ALLOW"
            },
            {
                "name": "Legit Mobile User-Agent",
                "headers": default_headers,
                "payload": {"action": "login"},
                "expected": "ALLOW"
            },
            {
                "name": "Legit JSON Body",
                "headers": default_headers,
                "payload": {"comment": "Hello, I need help with my account"},
                "expected": "ALLOW"
            },

            # =====================
            # OWASP TOP 10 – 2025
            # =====================

            # A01 – Broken Access Control
            {
                "name": "Access Admin Endpoint",
                "headers": default_headers,
                "payload": {"path": "/admin/deleteUser"},
                "expected": "BLOCK"
            },

            # A02 – Security Misconfiguration
            {
                "name": "Exposed Debug Parameter",
                "headers": default_headers,
                "payload": {"debug": "true"},
                "expected": "BLOCK"
            },

            # A03 – Software Supply Chain Failures
            {
                "name": "Malicious Dependency Injection",
                "headers": default_headers,
                "payload": {"dependency": "malicious-package@latest"},
                "expected": "BLOCK"
            },

            # A04 – Cryptographic Failures
            {
                "name": "Weak Crypto Usage",
                "headers": default_headers,
                "payload": {"password": "md5(password)"},
                "expected": "BLOCK"
            },

            # A05 – Injection
            {
                "name": "SQL Injection OR 1=1",
                "headers": default_headers,
                "payload": {"username": "' OR 1=1 --"},
                "expected": "BLOCK"
            },

            # A06 – Insecure Design
            {
                "name": "Client Side Trust Abuse",
                "headers": default_headers,
                "payload": {"isAdmin": "true"},
                "expected": "BLOCK"
            },

            # A07 – Authentication Failures
            {
                "name": "Brute Force Indicator",
                "headers": default_headers,
                "payload": {"username": "admin", "password": "admin"},
                "expected": "BLOCK"
            },

            # A08 – Software or Data Integrity Failures
            {
                "name": "Unsigned Update Attempt",
                "headers": default_headers,
                "payload": {"update": "firmware.bin"},
                "expected": "BLOCK"
            },

            # A09 – Security Logging and Alerting Failures
            {
                "name": "Log Tampering Attempt",
                "headers": default_headers,
                "payload": {"logLevel": "OFF"},
                "expected": "BLOCK"
            },

            # A10 – Mishandling Exceptional Conditions
            {
                "name": "Stack Trace Injection",
                "headers": default_headers,
                "payload": {"error": "Exception at line 42"},
                "expected": "BLOCK"
            }
        ]

