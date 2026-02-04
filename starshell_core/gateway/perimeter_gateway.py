# starshell_core/gateway/perimeter_gateway.py

import uvicorn
import httpx
import os
import json
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from starshell_core.bot.telemetry import TelemetryExtractor
from starshell_core.waf.middleware import WAFProtectionMiddleware
from starshell_core.logparser.log_analizer import LogAnalizer

app = FastAPI(title="StarShell Perimeter Gateway")
waf = WAFProtectionMiddleware()

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8080")
async_client = httpx.AsyncClient(base_url=BACKEND_URL)

@app.middleware("http")
async def security_logic(request: Request, call_next):
    # --- 1. BOT CHECK ---
    telemetry = await TelemetryExtractor.extract(request)
    ua = telemetry.get("user_agent", "") or ""
    
    # DO NOT rely on the class here; define the strict rule in the Gateway
    is_bot = not ua or "curl" in ua.lower() or "python-requests" in ua.lower()
    
    if is_bot:
        return JSONResponse(status_code=403, content={"message": "Bot blocked by StarShell"})

    # --- 2. WAF CHECK ---
    log_analyzer = LogAnalizer(httpRequestData=request)
    payload = await log_analyzer.extractAllHTTPPostData()
    waf_decision = waf.evaluate(payload)

    # FIX: Block on MEDIUM, HIGH, and CRITICAL for the Security Suite
    if waf_decision["action"] in ["BLOCK", "FLAG"]: # Treat FLAG as BLOCK for testing
        return JSONResponse(status_code=403, content={"message": "WAF Blocked", "waf": waf_decision})

    # --- 3. PROXY (The Tunnel) ---
    path = request.url.path
    method = request.method

    try:

        headers = dict(request.headers)
        headers.pop("host", None)
        headers["X-StarShell-Verified"] = "True"
        headers["X-StarShell-WAF-Decision"] = json.dumps(waf_decision)
        headers["X-StarShell-Bot-Score"] = str(telemetry.get("score", 0))

        # Use the captured body from the payload to avoid re-reading the stream
        sent_body = payload.get("body")
        
        # Ensure dicts are stringified for the wire
        if isinstance(sent_body, dict):
            sent_body = json.dumps(sent_body)
        elif sent_body is None:
            sent_body = b""

        resp = await async_client.request(
            method, 
            path, 
            headers=headers, 
            content=sent_body if method != "GET" else None,
            params=dict(request.query_params)
        )
        
        return Response(
            content=resp.content, 
            status_code=resp.status_code, 
            headers=dict(resp.headers)
        )
    except Exception as e:
        return JSONResponse(status_code=502, content={"message": f"Proxy Error: {str(e)}"})

if __name__ == "__main__":
    uvicorn.run("starshell_core.gateway.perimeter_gateway:app", host="0.0.0.0", port=8000, reload=True)
