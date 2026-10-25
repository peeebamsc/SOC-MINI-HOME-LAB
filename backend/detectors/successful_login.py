"""
SOC//LAB Detection Rule SOC-002.

Detects a successful Windows login after repeated
failed authentication attempts from the same
source IP and username.
"""

from collections import defaultdict
from datetime import timedelta

from backend.models.security_event import SecurityEvent


def detect_success_after_failures(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[dict]:
    """Detect successful authentication following repeated failures."""

    if threshold < 1 or window_minutes <= 0:
        raise ValueError("Threshold and window must be positive")

    grouped = defaultdict(list)

    for event in events:
        if event.event_id in (4624, 4625):
            key = (event.source_ip, event.username)
            grouped[key].append(event)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for (source_ip, username), authentication_events in grouped.items():

        authentication_events.sort(
            key=lambda event: event.timestamp
        )

        failures = []

        for event in authentication_events:

            if event.event_id == 4625:
                failures.append(event)
                continue

            # Event ID 4624: successful authentication.
            cutoff = event.timestamp - window

            failures = [
                failure
                for failure in failures
                if failure.timestamp >= cutoff
            ]

            if len(failures) >= threshold:
                alerts.append(
                    {
                        "rule_id": "SOC-002",
                        "rule": "Successful Login After Repeated Failures",
                        "severity": "high",
                        "source_ip": source_ip,
                        "username": username,
                        "failed_attempts": len(failures),
                        "first_seen": failures[0].timestamp.isoformat(),
                        "last_seen": event.timestamp.isoformat(),
                        "status": "open",
                    }
                )

            # Reset after each successful login so that
            # earlier failures are not counted again.
            failures = []

    return alerts