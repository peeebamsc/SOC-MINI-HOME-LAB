import json
from pathlib import Path

from backend.detectors.failed_login import detect_failed_logins
from backend.models.security_event import SecurityEvent


def main():
    path = Path("data/events.json")

    if not path.exists():
        print("No security events found. Run the event generator first.")
        return

    raw_events = json.loads(path.read_text(encoding="utf-8"))

    events = [SecurityEvent.model_validate(item) for item in raw_events]

    alerts = detect_failed_logins(events)

    print(f"Events analyzed: {len(events)}")
    print(f"Security alerts generated: {len(alerts)}")

    for alert in alerts:
        print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
