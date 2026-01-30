import re
import logging
from typing import Dict, List
from star_defense.waf.rules.core_rules import CoreRules
from star_defense.waf.rules.owasp_2025_rules import OWASP2025Rules

logger = logging.getLogger("uvicorn.error")


class WAFEngine:
    def __init__(self):
        logger.info("/WAFEngine Initialized")
        self.rules = self.load_rules()

    def load_rules(self):
        rules = []
        rules.extend(CoreRules.load_legit_rules())
        rules.extend(OWASP2025Rules.load_owasp_2025_rules())
        return rules


    def evaluate(self, request_payload: Dict) -> Dict:
        """
        Evaluate HTTP request against WAF rules
        """
        logger.info("/WAFEngine.evaluate Evaluation Started")

        matches = []

        for rule in self.rules:
            for target in rule.get("targets", ["body", "headers"]):
                value = self.extract_target_value(request_payload, target)

                if not value:
                    continue

                if re.search(rule["pattern"], str(value)): # Checking if a WAF Rule matches the value on the HTTP Request
                    matches.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule.get("category", "UNKNOWN"),
                        "severity": rule["severity"],
                        "target": target,
                        "matched_value": str(value)[:200]
                    })

        print(matches)
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

        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        highest = max(matches, key=lambda x: severity_order[x["severity"]])

        if highest["severity"] == "HIGH" or highest["severity"] == "CRITICAL":
            action = "BLOCK"
        elif highest["severity"] == "MEDIUM":
            action = "FLAG"
        else:
            action = "ALLOW"

        # action = "BLOCK" if highest["severity"] == ("HIGH" or "CRITICAL") else "FLAG"

        return {
            "action": action,
            "confidence": round(0.6 + (0.1 * len(matches)), 2), # (?)
            "primary_rule": highest,
            "matches": matches
        }
