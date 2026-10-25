import json
from pathlib import Path

from backend.models.security_event import SecurityEvent
from backend.detectors.failed_login import detect_failed_logins
from backend.storage.database import (
    initialize_database,
    save_events,
    save_alerts,
    get_event_count,
    get_alert_count,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVENTS_FILE = PROJECT_ROOT / "data" / "events.json"


def main():
    initialize_database()

    with EVENTS_FILE.open("r", encoding="utf-8") as file:
        raw_events = json.load(file)

    # Validate the synthetic security events.
    events = [
        SecurityEvent.model_validate(event)
        for event in raw_events
    ]

    # Generate alerts using the existing detection engine.
    alerts = detect_failed_logins(events)

    # Persist the events and alerts.
    save_events(events)
    save_alerts(alerts)

    print("SOC//LAB SQLite Import")
    print("----------------------")
    print(f"Events processed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Stored events: {get_event_count()}")
    print(f"Stored alerts: {get_alert_count()}")


if __name__ == "__main__":
    main()