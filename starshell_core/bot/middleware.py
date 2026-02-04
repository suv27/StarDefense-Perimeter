# starshell_core/bot/middleware.py

from fastapi import Request
from starshell_core.bot.telemetry import TelemetryExtractor
from fastapi.responses import JSONResponse

class BotProtectionMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Use the existing scope to create a temporary request object
        request = Request(scope, receive=receive)
        telemetry = await TelemetryExtractor.extract(request)

        # 1. Logic: Determine if it's a bot
        user_agent = telemetry.get("user_agent", "") or ""
        is_bot = not user_agent or "curl" in user_agent.lower()
        
        # 2. Add the key that backend_apis.py is looking for
        telemetry["is_bot"] = is_bot

        # 3. CRITICAL: Save it directly to the scope
        # This makes it accessible via request.state.bot_telemetry in your API
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["bot_telemetry"] = telemetry

        # 4. Optional: Block immediately if it's a bot
        if is_bot:
            response = JSONResponse(
                status_code=403,
                content={"detail": "Bot blocked by StarShell"}
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)