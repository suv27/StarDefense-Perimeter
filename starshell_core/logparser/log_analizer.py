# starshell_core/logparser/log_analizer.py

import logging
import json
import datetime
from fastapi import Request

logger = logging.getLogger("uvicorn.error")

class LogAnalizer:
    def __init__(self, httpRequestData: Request):
        self.request = httpRequestData
        logger.info(f"🛡️ LogAnalizer: New request for {self.request.url.path}")
    
    async def extractAllHTTPPostData(self):
        """Extracts and logs telemetry while preserving the request body."""
        
        # FIX: Read the body ONCE and store it
        raw_body = await self.request.body()
        
        # Try to parse as JSON, fallback to string if it's not JSON
        try:
            body_content = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            body_content = raw_body.decode("utf-8", "ignore")

        # Capture all relevant telemetry
        payload = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "method": self.request.method,
            "url": str(self.request.url),
            "client_ip": self.request.client.host if self.request.client else "unknown",
            "headers": dict(self.request.headers),
            "body": body_content,
            "security": {
                "user_agent": self.request.headers.get("user-agent"),
                "content_type": self.request.headers.get("content-type")
            }
        }

        # Log it in the high-performance JSONL format
        self.logPayload(payload)
        
        # Return the payload so the WAF can use it
        return payload

    def logPayload(self, parsedPayload):
        """Saves telemetry to a JSONL file for future dashboard use."""
        try:
            filename = "http_events_log.jsonl"
            with open(filename, "a", encoding="utf-8") as log_file:
                # One JSON object per line
                log_file.write(json.dumps(parsedPayload) + "\n")
        except Exception as e:
            logger.error(f"❌ Logging Error: {e}")
