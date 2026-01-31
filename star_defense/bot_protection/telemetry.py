# star_defense/bot_protection/telemetry.py

from fastapi import Request
import time

class TelemetryExtractor:
    @staticmethod
    async def extract(request: Request) -> dict:
        body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()

        telemetry = {
            "ip": request.client.host if request.client else "unknown",
            "method": request.method,
            "path": request.url.path,
            "user_agent": request.headers.get("user-agent", ""),
            "content_type": request.headers.get("content-type", ""),
            "header_count": len(request.headers),
            "body_size": len(body),
            "timestamp": time.time(),
        }

        return telemetry
