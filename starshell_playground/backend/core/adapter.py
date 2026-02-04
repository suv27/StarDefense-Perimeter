# starshell_playground/backend/core/adapter.py

import json
from fastapi import Request

class SecurityAdapter:
    @staticmethod
    def capture_decision(request: Request):
        # Extract the decision sent by the StarShell Perimeter Gateway
        waf_header = request.headers.get("X-StarShell-WAF-Decision")
        bot_header = request.headers.get("X-StarShell-Bot-Score")

        # 2. Parse the WAF JSON (or default to ALLOW if missing)
        waf_data = json.loads(waf_header) if waf_header else {"action": "ALLOW"}
        
        return {
            "verdict": waf_data.get("action", "ALLOW"),
            "bot_layer": {
                "score": float(bot_header) if bot_header else 0.0,
            },
            "waf_layer": {
                "action": waf_data.get("action"),
                "primary_rule": waf_data.get("primary_rule", {}),
                "matches": waf_data.get("matches", [])
            }
        }