"""
SOC//LAB Automated Tests — SOC-002.

Tests successful authentication after repeated
failed Windows login attempts.
"""

from datetime import datetime, timedelta, timezone

from backend.detectors.successful_login import detect_success_after_failures
from backend.models.security_event import SecurityEvent


BASE_TIME = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


def make_event(
    event_id,
    minute,
    username="analyst",
    source_ip="192.0.2.20",
):
    """Create a synthetic Windows authentication event."""

    return SecurityEvent(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(minutes=minute),
        username=username,
        source_ip=source_ip,
        hostname="SOC-LAB-WIN10",
        message="Synthetic Windows authentication event",
    )


def test_success_after_three_failures():
    """Three failures followed by success should trigger SOC-002."""

    events = [
        make_event(4625, 0),
        make_event(4625, 1),
        make_event(4625, 2),
        make_event(4624, 3),
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOC-002"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["failed_attempts"] == 3
    assert alerts[0]["username"] == "analyst"
    assert alerts[0]["source_ip"] == "192.0.2.20"


def test_insufficient_failures():
    """Two failures followed by success should not trigger an alert."""

    events = [
        make_event(4625, 0),
        make_event(4625, 1),
        make_event(4624, 2),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_failures_outside_time_window():
    """Failures older than five minutes should not trigger an alert."""

    events = [
        make_event(4625, 0),
        make_event(4625, 1),
        make_event(4625, 2),
        make_event(4624, 10),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_different_usernames():
    """Failures from different users must not be combined."""

    events = [
        make_event(4625, 0, username="analyst"),
        make_event(4625, 1, username="administrator"),
        make_event(4625, 2, username="analyst"),
        make_event(4624, 3, username="analyst"),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_different_source_ips():
    """Failures from different IPs must not be combined."""

    events = [
        make_event(4625, 0, source_ip="192.0.2.20"),
        make_event(4625, 1, source_ip="192.0.2.15"),
        make_event(4625, 2, source_ip="192.0.2.20"),
        make_event(4624, 3, source_ip="192.0.2.20"),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_success_resets_failure_sequence():
    """A previous successful login resets the failure counter."""

    events = [
        make_event(4625, 0),
        make_event(4625, 1),
        make_event(4624, 2),
        make_event(4625, 3),
        make_event(4624, 4),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []