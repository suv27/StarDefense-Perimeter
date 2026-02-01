import re
import json
import logging
from typing import Dict, List
from star_defense.waf.rules.core_rules import CoreRules
from star_defense.waf.rules.signature_database import SignatureDB

logger = logging.getLogger("uvicorn.error")


class WAFProtectionMiddleware:
    def __init__(self):
        logger.info("/WAFProtectionMiddleware Initialized")
        self.rules = self.load_rules()

    def load_rules(self):
        rules = []
        rules.extend(CoreRules.load_legit_rules())
        rules.extend(SignatureDB.load_owasp_2025_rules())
        return rules


    def evaluate(self, request_payload: Dict) -> Dict:
        logger.info("/WAFProtectionMiddleware.evaluate Evaluation Started")
        matches = []

        for rule in self.rules:
            for target in rule.get("targets", ["body", "headers"]):
                value = self.extract_target_value(request_payload, target)

                if not value:
                    continue

                # NEW: If the target is 'body' and it's a dict, flatten it properly
                if target == "body" and isinstance(value, dict):
                    search_string = json.dumps(value)
                else:
                    search_string = str(value)

                # Now search against the flattened string
                if re.search(rule["pattern"], search_string):
                    matches.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule.get("category", "UNKNOWN"),
                        "severity": rule["severity"],
                        "target": target,
                        "matched_value": search_string[:200]
                    })

        print(f"DEBUG: Matches found: {len(matches)}")
        decision = self.make_decision(matches)
        logger.info(f"/WAFProtectionMiddleware Decision: {decision['action']}")
        return decision

    def extract_target_value(self, payload: Dict, target: str):
        """
        Safely extract and normalize values from the HTTP payload for regex matching.
        """
        # 1. Body Handling (Crucial for JSON attacks)
        if target == "body":
            body_data = payload.get("body")
            if isinstance(body_data, dict):
                # Flatten dict to JSON string so regex can see "key": "value"
                return json.dumps(body_data)
            return str(body_data) if body_data else ""

        # 2. Query String / Params Handling
        if target == "query_string":
            # Check both common names for query data
            qs = payload.get("query_string") or payload.get("params") or payload.get("args")
            if isinstance(qs, dict):
                return json.dumps(qs)
            return str(qs) if qs else ""

        # 3. Path / URL Handling
        if target == "path":
            return str(payload.get("path", ""))

        # 4. Headers / Metadata Handling
        if target == "headers":
            headers = payload.get("headers", {})
            # Flatten headers so we can search for things like 'User-Agent: bot'
            return json.dumps(headers)

        if target == "user_agent":
            # Specific shortcut for user-agent rules
            return str(payload.get("user_agent") or payload.get("headers", {}).get("User-Agent", ""))

        return None

    def make_decision(self, matches: List[Dict]) -> Dict:
        if not matches:
            return {"action": "ALLOW", "confidence": 1.0, "matches": []}

        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        highest = max(matches, key=lambda x: severity_order[x["severity"]])

        # RECOMMENDATION: In a real WAF, MEDIUM can be FLAG, 
        # but for a "Security Perimeter," we usually BLOCK MEDIUM and above.
        if highest["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]:
            action = "BLOCK"
        else:
            action = "ALLOW"

        return {
            "action": action,
            "confidence": round(0.6 + (0.1 * len(matches)), 2),
            "primary_rule": highest,
            "matches": matches
        }
