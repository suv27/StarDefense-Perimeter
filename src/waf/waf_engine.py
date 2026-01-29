import re
import logging
from typing import Dict, List

logger = logging.getLogger("uvicorn.error")


class WAFEngine:
    def __init__(self):
        logger.info("/WAFEngine Initialized")
        self.rules = self.load_rules()

    def load_rules(self) -> List[Dict]:
        """
        Static rule set for Phase 1.
        Later this can be loaded from JSON/YAML or DB.
        """
        return [
            {
                "id": "SQLI_001",
                "name": "SQL Injection Attempt",
                "category": "SQLi",
                "severity": "HIGH",
                "pattern": r"(?i)(union\s+select|select\s+.*from|drop\s+table|or\s+1=1)",
                "targets": ["body", "query_string"]
            },
            {
                "id": "XSS_001",
                "name": "Cross-Site Scripting Attempt",
                "category": "XSS",
                "severity": "HIGH",
                "pattern": r"(?i)(<script>|onerror=|onload=|<img\s+src)",
                "targets": ["body"]
            },
            {
                "id": "PATH_001",
                "name": "Path Traversal Attempt",
                "category": "Traversal",
                "severity": "MEDIUM",
                "pattern": r"(\.\./|\.\.\\|%2e%2e)",
                "targets": ["path"]
            },
            {
                "id": "UA_001",
                "name": "Suspicious User-Agent",
                "category": "Recon",
                "severity": "LOW",
                "pattern": r"(?i)(sqlmap|nikto|nmap|curl|wget)",
                "targets": ["user_agent"]
            }
        ]

    def evaluate(self, request_payload: Dict) -> Dict:
        """
        Evaluate HTTP request against WAF rules
        """
        logger.info("/WAFEngine.evaluate Evaluation Started")

        matches = []

        for rule in self.rules:
            for target in rule["targets"]:
                value = self.extract_target_value(request_payload, target)

                if not value:
                    continue

                if re.search(rule["pattern"], str(value)): # Checking if a WAF Rule matches the value on the HTTP Request
                    matches.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "target": target,
                        "matched_value": str(value)[:200]
                    })

        decision = self.make_decision(matches)
        logger.info(f"/WAFEngine Decision: {decision['action']}")
        return decision

    def extract_target_value(self, payload: Dict, target: str):
        """
        Safely extract values from normalized HTTP payload
        """
        if target == "body":
            return payload.get("body")

        if target == "query_string":
            return payload.get("query_string")

        if target == "path":
            return payload.get("path")

        if target == "user_agent":
            return payload.get("user_agent")

        return None

    def make_decision(self, matches: List[Dict]) -> Dict:
        """
        Aggregate rule matches into a single verdict
        """
        if not matches:
            return {
                "action": "ALLOW",
                "confidence": 1.0,
                "matches": []
            }

        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        highest = max(matches, key=lambda x: severity_order[x["severity"]])

        action = "BLOCK" if highest["severity"] == "HIGH" else "FLAG"

        return {
            "action": action,
            "confidence": round(0.6 + (0.1 * len(matches)), 2), # (?)
            "primary_rule": highest,
            "matches": matches
        }
