"""
SOC//LAB Detection Integration Tests.

Verifies SOC-001 and SOC-002 detection,
SQLite persistence, duplicate prevention,
and event-driven detection behavior.

Uses temporary SQLite databases.
"""

from datetime import datetime, timedelta, timezone

from backend.models.security_event import SecurityEvent
from backend.simulator import event_simulator
from backend.storage import database


def make_event(event_id, timestamp):
    """Create a synthetic Windows authentication event."""
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        username="analyst",
        source_ip="192.0.2.20",
        hostname="SOC-WIN10",
        message=(
            "An account failed to log on"
            if event_id == 4625
            else "An account was successfully logged on"
        ),
    )


def test_both_detection_rules_persist_alerts(tmp_path, monkeypatch):
    """Verify SOC-001 and SOC-002 persistence and deduplication."""

    monkeypatch.setattr(
        database,
        "DB_PATH",
        tmp_path / "soc_lab_integration.db",
    )

    database.initialize_database()

    base_time = datetime.now(timezone.utc) - timedelta(minutes=2)

    events = [
        make_event(event_id, base_time + timedelta(seconds=index * 10))
        for index, event_id in enumerate([4625, 4625, 4625, 4624])
    ]

    database.save_events(events)

    results = event_simulator.process_detections()

    assert results["SOC-001"] == 1
    assert results["SOC-002"] == 1

    stored_alerts = database.get_all_alerts()

    assert len(stored_alerts) == 2
    assert {alert["rule_id"] for alert in stored_alerts} == {
        "SOC-001",
        "SOC-002",
    }

    soc002_alert = next(
        alert
        for alert in stored_alerts
        if alert["rule_id"] == "SOC-002"
    )

    assert soc002_alert["username"] == "analyst"
    assert soc002_alert["source_ip"] == "192.0.2.20"
    assert soc002_alert["failed_attempts"] == 3
    assert soc002_alert["severity"] == "high"

    # Reprocessing identical events must not create duplicate alerts.
    initial_alert_count = database.get_alert_count()

    second_results = event_simulator.process_detections()

    assert second_results == {
        "SOC-001": 0,
        "SOC-002": 0,
    }

    assert database.get_alert_count() == initial_alert_count


def test_event_driven_detection_ignores_previous_success(
    tmp_path,
    monkeypatch,
):
    """A new failed login must not alert on an earlier success."""

    monkeypatch.setattr(
        database,
        "DB_PATH",
        tmp_path / "soc_lab_event_driven.db",
    )

    database.initialize_database()

    base_time = datetime.now(timezone.utc) - timedelta(minutes=2)

    historical_events = [
        make_event(4625, base_time),
        make_event(4625, base_time + timedelta(seconds=10)),
        make_event(4625, base_time + timedelta(seconds=20)),
        make_event(4624, base_time + timedelta(seconds=30)),
    ]

    database.save_events(historical_events)

    # A new failure occurs after the historical successful login.
    trigger_event = make_event(
        4625,
        base_time + timedelta(seconds=40),
    )

    database.save_events([trigger_event])

    results = event_simulator.process_detections(
        trigger_event=trigger_event
    )

    assert results["SOC-001"] == 0
    assert results["SOC-002"] == 0
    assert database.get_alert_count() == 0


def test_event_driven_success_creates_one_alert(tmp_path, monkeypatch):
    """A qualifying successful login creates exactly one SOC-002 alert."""

    monkeypatch.setattr(
        database,
        "DB_PATH",
        tmp_path / "soc_lab_success.db",
    )
    database.initialize_database()

    base_time = datetime.now(timezone.utc) - timedelta(minutes=2)

    failures = [
        make_event(4625, base_time + timedelta(seconds=index * 10))
        for index in range(3)
    ]

    database.save_events(failures)

    success = make_event(
        4624,
        base_time + timedelta(seconds=30),
    )
    database.save_events([success])

    first_results = event_simulator.process_detections(
        trigger_event=success
    )

    assert first_results == {
        "SOC-001": 0,
        "SOC-002": 1,
    }

    alerts = database.get_all_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOC-002"
    assert alerts[0]["failed_attempts"] == 3

    # Reprocessing the same successful event must not duplicate the alert.
    second_results = event_simulator.process_detections(
        trigger_event=success
    )

    assert second_results == {
        "SOC-001": 0,
        "SOC-002": 0,
    }

    assert database.get_alert_count() == 1