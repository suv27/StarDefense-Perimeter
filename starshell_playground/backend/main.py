# starshell_playground/backend/main.py

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starshell_playground.backend.api.simulate import router as simulate_router
from starshell_playground.backend.api.target import router as app_router
from starshell_playground.backend.api.management import router as mgmt_router

app = FastAPI(title="StarShell Security Playground")
app.add_middleware(
    CORSMiddleware,      # Enable CORS so your future Frontend (React/Vue) can talk to this API
    allow_origins=["*"], # In production, we'll restrict this
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(simulate_router, prefix="/api/simulate", tags=["Simulator"])
app.include_router(app_router, prefix="/api/app", tags=["Target App"])
app.include_router(mgmt_router, prefix="/api/management", tags=["Management"])



@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "engine": "StarShell v1.2",
        "layers": ["BOT", "WAF", "LogParser"]
    }

