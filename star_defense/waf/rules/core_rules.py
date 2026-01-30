class CoreRules:
    def load_legit_rules():
        return [
            {
                "id": "LEGIT-001",
                "name": "Valid Email Address",
                "owasp": "LEGIT",
                "type": "LEGIT",
                "pattern": r"^[\w\.-]+@[\w\.-]+\.\w+$",
                "severity": "LOW",
                "action": "ALLOW"
            },
            {
                "id": "LEGIT-002",
                "name": "Strong Password Pattern",
                "owasp": "LEGIT",
                "type": "LEGIT",
                "pattern": r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*#?&]).{8,}$",
                "severity": "LOW",
                "action": "ALLOW"
            },
            {
                "id": "LEGIT-003",
                "name": "UUID Identifier",
                "owasp": "LEGIT",
                "type": "LEGIT",
                "pattern": r"^[0-9a-fA-F-]{36}$",
                "severity": "LOW",
                "action": "ALLOW"
            },
            {
                "id": "LEGIT-004",
                "name": "JWT Token Format",
                "owasp": "LEGIT",
                "type": "LEGIT",
                "pattern": r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$",
                "severity": "LOW",
                "action": "ALLOW"
            },
            {
                "id": "LEGIT-005",
                "name": "Standard Username",
                "owasp": "LEGIT",
                "type": "LEGIT",
                "pattern": r"^[a-zA-Z0-9_]{3,30}$",
                "severity": "LOW",
                "action": "ALLOW"
            }
        ]