# starshell_playground/backend/core/storage.py

from datetime import datetime
from typing import List, Dict

class EventStore:
    # We'll keep the last 100 events in memory
    _history: List[Dict] = []
    _limit = 100

    @classmethod
    def add_event(cls, insight: Dict, raw_payload: Dict):
        event = {
            "id": len(cls._history) + 1,
            "timestamp": datetime.now().isoformat(),
            "verdict": insight["verdict"],
            "waf_details": insight["waf_layer"],
            "bot_details": insight["bot_layer"],
            "payload_preview": raw_payload
        }
        cls._history.insert(0, event) # Newest first
        
        # Keep it from growing forever
        if len(cls._history) > cls._limit:
            cls._history.pop()

    @classmethod
    def get_all(cls):
        return cls._history
    
    @classmethod
    def get_stats(cls):
        return cls.get_stats