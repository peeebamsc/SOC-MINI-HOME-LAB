from collections import defaultdict
from datetime import timedelta

from backend.models.security_event import SecurityEvent


def detect_failed_logins(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[dict]:
    """Detect repeated failed logins from the same source IP."""

    if threshold < 1 or window_minutes <= 0:
        raise ValueError("Threshold and window must be positive")

    grouped = defaultdict(list)

    for event in events:
        if event.event_id == 4625:
            grouped[event.source_ip].append(event)

    alerts = []

    for source_ip, failures in grouped.items():
        failures.sort(key=lambda event: event.timestamp)

        left = 0

        for right, event in enumerate(failures):
            while (
                event.timestamp - failures[left].timestamp
                > timedelta(minutes=window_minutes)
            ):
                left += 1

            count = right - left + 1

            if count == threshold:
                alerts.append(
                    {
                        "rule_id": "SOC-001",
                        "rule": "Repeated Failed Authentication",
                        "severity": "medium",
                        "source_ip": source_ip,
                        "failed_attempts": count,
                        "first_seen": failures[left].timestamp.isoformat(),
                        "last_seen": event.timestamp.isoformat(),
                        "status": "open",
                    }
                )

    return alerts
