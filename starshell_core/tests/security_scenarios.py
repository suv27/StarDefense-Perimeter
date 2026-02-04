# starshell_core/tests/security_scenarios.py

class TestCases:
    @staticmethod
    def load_bot_test_cases():
        return [
            {
                "name": "Bot Check: Legit Browser",
                "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
                "payload": {"username": "user", "password": "pass"},
                "expect_status": 200
            },
            {
                "name": "Bot Check: No User Agent",
                "headers": {"Content-Type": "application/json"},
                "payload": {"username": "bot", "password": "bot"},
                "expect_status": 403
            },
            {
                "name": "Bot Check: Curl User Agent",
                "headers": {"User-Agent": "curl/7.68.0", "Content-Type": "application/json"},
                "payload": {"username": "bot", "password": "bot"},
                "expect_status": 403
            }
        ]
    
    @staticmethod
    def load_waf_test_cases():
        default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) StarShell/1.1"
        }
        return [
            # ==================================================
            # LEGITIMATE REQUESTS (Must pass BOT + WAF)
            # ==================================================
            {
                "name": "Legit: User Login",
                "headers": default_headers,
                "payload": {"user": "starlyn_dev", "token": "a1b2c3d4e5"},
                "expected": "ALLOW"
            },
            {
                "name": "Legit: Search Product",
                "headers": default_headers,
                "payload": {"query": "cybersecurity books", "limit": 10},
                "expected": "ALLOW"
            },
            {
                "name": "Legit: Update Profile",
                "headers": default_headers,
                "payload": {"bio": "Security Enthusiast", "location": "NYC"},
                "expected": "ALLOW"
            },
            {
                "name": "Legit: Support Ticket",
                "headers": default_headers,
                "payload": {"subject": "Help", "msg": "I forgot my password"},
                "expected": "ALLOW"
            },
            {
                "name": "Legit: Add to Cart",
                "headers": default_headers,
                "payload": {"item_id": 992, "qty": 1},
                "expected": "ALLOW"
            },

            # ==================================================
            # OWASP TOP 10 - REAL WORLD ATTACKS (Must be BLOCKED)
            # ==================================================

            # A01: Broken Access Control (Path Traversal)
            {
                "name": "Attack: Directory Traversal",
                "headers": default_headers,
                "payload": {"file": "../../../etc/passwd"},
                "expected": "BLOCK"
            },

            # A02: Cryptographic Failures (Hardcoded Weak Hash)
            {
                "name": "Attack: MD5 Hash Submission",
                "headers": default_headers,
                "payload": {"hash_type": "md5", "val": "5f4dcc3b5aa765d6"},
                "expected": "BLOCK"
            },

            # A03: Injection (Polyglot SQLi)
            {
                "name": "Attack: Advanced SQL Injection",
                "headers": default_headers,
                "payload": {"id": "1; DROP TABLE users;--"},
                "expected": "BLOCK"
            },

            # A04: Insecure Design (Privilege Escalation)
            {
                "name": "Attack: Admin Role Manipulation",
                "headers": default_headers,
                "payload": {"user_id": 101, "is_admin": True},
                "expected": "BLOCK"
            },

            # A05: Security Misconfiguration (Debug Leak)
            {
                "name": "Attack: Remote Debug Activation",
                "headers": default_headers,
                "payload": {"settings": {"debug": "on", "show_env": 1}},
                "expected": "BLOCK"
            },

            # A06: Vulnerable Components (Package Hijacking)
            {
                "name": "Attack: Malicious Pip Install",
                "headers": default_headers,
                "payload": {"cmd": "pip install pwned-package@1.3.3.7"},
                "expected": "BLOCK"
            },

            # A07: Identification Failures (Default Creds)
            {
                "name": "Attack: Default Admin Login",
                "headers": default_headers,
                "payload": {"user": "root", "pass": "root"},
                "expected": "BLOCK"
            },

            # A08: Integrity Failures (Unsigned Binary)
            {
                "name": "Attack: Firmware Hijack",
                "headers": default_headers,
                "payload": {"upload": "malicious_update.bin", "sig": "none"},
                "expected": "BLOCK"
            },

            # A09: Logging Failures (Log Clearing)
            {
                "name": "Attack: Log Suppression",
                "headers": default_headers,
                "payload": {"action": "delete", "target": "system.log"},
                "expected": "BLOCK"
            },

            # A10: SSRF (Internal Meta-Data Access)
            {
                "name": "Attack: SSRF Metadata Query",
                "headers": default_headers,
                "payload": {"url": "http://169.254.169.254/latest/meta-data/"},
                "expected": "BLOCK"
            }
        ]
