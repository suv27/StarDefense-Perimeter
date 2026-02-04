# starshell_playground/backend/api/management.py

from fastapi import APIRouter
from starshell_playground.backend.core.storage import EventStore
from starshell_core.waf.rules.signature_database import SignatureDB

router = APIRouter()

@router.get("/history")
async def get_history():
    """Returns the live feed of security events."""
    return EventStore.get_all()

@router.get("/stats")
async def get_stats():
    """Returns aggregated data for the dashboard charts."""
    return EventStore.get_stats()

@router.get("/signatures")
async def get_signatures():
    """Returns the OWASP 2025 rule set for the UI to display."""
    # This allows users to read the regex patterns they are trying to bypass
    return SignatureDB.load_owasp_2025_rules()