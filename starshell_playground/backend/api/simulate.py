# starshell_playground/backend/api/simulate.py

from fastapi import APIRouter, Request
from starshell_playground.backend.core.adapter import SecurityAdapter
from starshell_playground.backend.core.storage import EventStore

router = APIRouter()

@router.api_route("/request", methods=["GET", "POST"])
async def process_simulation(request: Request):
    insight = SecurityAdapter.capture_decision(request)
    
    # NEW: Store the event for the UI
    EventStore.add_event(insight, request.body)
    
    return {
        "message": "Simulation Processed",
        "waf": insight["waf_layer"],
        "bot": insight["bot_layer"],
        "verdict": insight["verdict"]
    }

@router.get("/history")
async def get_history():
    # This is what the Frontend will fetch every few seconds
    return EventStore.get_all()