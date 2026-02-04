# starshell_playground/backend/api/target.py

from fastapi import APIRouter, Request, Body
from starshell_playground.backend.core.adapter import SecurityAdapter
from starshell_playground.backend.core.storage import EventStore

router = APIRouter()

def handle_security_event(request: Request, payload: dict):
    """Internal helper to log the event and return the decision."""
    insight = SecurityAdapter.capture_decision(request)
    EventStore.add_event(insight, payload)
    return insight

@router.post("/login")
async def login(request: Request, data: dict = Body(...)):
    insight = handle_security_event(request, data)
    return {"message": "Login processed", "security": insight}

@router.post("/submit-ticket")
async def ticket(request: Request, data: dict = Body(...)):
    insight = handle_security_event(request, data)
    return {"message": "Ticket received", "security": insight}

@router.get("/search")
async def search(request: Request):
    params = dict(request.query_params)
    insight = handle_security_event(request, params)
    return {"results": [], "security": insight}