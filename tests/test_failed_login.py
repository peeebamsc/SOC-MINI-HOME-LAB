from datetime import datetime, timedelta, timezone

from backend.detectors.failed_login import detect_failed_logins
from backend.models.security_event import SecurityEvent


def make_event(event_id, source_ip, timestamp):
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        username="lab-user",
        source_ip=source_ip,
        hostname="SOC-LAB-WIN10",
        message="Synthetic authentication event",
    )


def test_three_failed_logins_generate_alert():
    now = datetime.now(timezone.utc)

    events = [
        make_event(4625, "192.0.2.15", now + timedelta(seconds=i * 30))
        for i in range(3)
    ]

    alerts = detect_failed_logins(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOC-001"
    assert alerts[0]["failed_attempts"] == 3


def test_successful_logins_do_not_generate_alert():
    now = datetime.now(timezone.utc)

    events = [
        make_event(4624, "192.0.2.15", now + timedelta(seconds=i * 30))
        for i in range(3)
    ]

    assert detect_failed_logins(events) == []


def test_different_ips_do_not_combine_failures():
    now = datetime.now(timezone.utc)

    events = [
        make_event(4625, "192.0.2.15", now),
        make_event(4625, "192.0.2.15", now + timedelta(seconds=30)),
        make_event(4625, "192.0.2.20", now + timedelta(seconds=60)),
    ]

    assert detect_failed_logins(events) == []


def test_failures_outside_window_do_not_generate_alert():
    now = datetime.now(timezone.utc)

    events = [
        make_event(4625, "192.0.2.15", now),
        make_event(4625, "192.0.2.15", now + timedelta(minutes=6)),
        make_event(4625, "192.0.2.15", now + timedelta(minutes=12)),
    ]

    assert detect_failed_logins(events) == []
