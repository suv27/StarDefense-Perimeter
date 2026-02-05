# starshell_playground/backend/api/main.py

from fastapi import FastAPI, Request, APIRouter, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starshell_playground.backend.core.storage import EventStore
from starshell_playground.backend.core.adapter import SecurityAdapter
from starshell_core.waf.rules.signature_database import SignatureDB

app = FastAPI(title="StarShell Security Playground")
app.add_middleware(
    CORSMiddleware,      # Enable CORS so your future Frontend (React/Vue) can talk to this API
    allow_origins=["*"], # In production, we'll restrict this
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

router = APIRouter()

@app.api_route("/api/simulate/request", methods=["GET", "POST"])
async def handle_security_event(request: Request):
    insight = SecurityAdapter.capture_decision(request)
    EventStore.add_event(insight, {})
    if insight["verdict"] == "BLOCK":
        return JSONResponse(status_code=403, content={"message": "Bot blocked by StarShell"})
    return insight

@app.post("/api/target-app/login")
async def login(request: Request, data: dict = Body(...)):
    insight = handle_security_event(request, data)
    return {"message": "Login processed", "security": insight}

@app.post("/api/target-app/submit-ticket")
async def ticket(request: Request, data: dict = Body(...)):
    insight = handle_security_event(request, data)
    return {"message": "Ticket received", "security": insight}

@app.get("/api/target-app/search")
async def search(request: Request):
    params = dict(request.query_params)
    insight = handle_security_event(request, params)
    return {"results": [], "security": insight}

@app.get("/api/management/stats")
async def get_stats():
    """Returns aggregated data for the dashboard charts."""
    return EventStore.get_stats()

@app.get("/api/management/signatures")
async def get_signatures():
    return SignatureDB.load_owasp_2025_rules()

@app.get("/api/management/history")
async def get_history():
    return EventStore.get_all()

@app.delete("/api/management/history")
async def clear_history():
    EventStore.clear()
    return {"message": "Playground history reset"}

@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "engine": "StarShell v1.2",
        "layers": ["BOT", "WAF", "LogParser"]
    }

