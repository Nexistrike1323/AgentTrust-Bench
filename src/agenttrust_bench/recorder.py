from datetime import datetime, timezone

class EventRecorder:
    def __init__(self):
        self._events = []

    def record(self, event_type, actor, **details):
        event = {
            "sequence": len(self._events) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "actor": actor,
            "details": details,
        }
        self._events.append(event)
        return event

    @property
    def events(self):
        return list(self._events)
