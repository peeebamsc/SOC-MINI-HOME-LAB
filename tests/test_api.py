"""
SOC//LAB - FastAPI Endpoint Tests

Tests:
1. API health
2. Security event retrieval
3. Security alert retrieval
4. Security statistics
5. Unknown endpoint handling
6. Controlled security event data

Run:
    python -m pytest tests/test_api.py -v
"""

from fastapi.testclient import TestClient

from backend.api import app as api_module


client = TestClient(api_module.app)


# --------------------------------------------------
# TEST 1: API HEALTH
# --------------------------------------------------

def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "soc-lab-api"
    assert data["version"] == "1.0.0"


# --------------------------------------------------
# TEST 2: SECURITY EVENTS
# --------------------------------------------------

def test_events_endpoint():
    response = client.get("/events")

    assert response.status_code == 200

    data = response.json()

    assert "total" in data
    assert "events" in data

    assert isinstance(data["events"], list)
    assert isinstance(data["total"], int)

    assert data["total"] == len(data["events"])


# --------------------------------------------------
# TEST 3: SECURITY ALERTS
# --------------------------------------------------

def test_alerts_endpoint():
    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.json()

    assert "total" in data
    assert "alerts" in data

    assert isinstance(data["alerts"], list)
    assert isinstance(data["total"], int)

    assert data["total"] == len(data["alerts"])


# --------------------------------------------------
# TEST 4: SECURITY STATISTICS
# --------------------------------------------------

def test_stats_endpoint():
    response = client.get("/stats")

    assert response.status_code == 200

    data = response.json()

    required_fields = [
        "total_events",
        "failed_logins",
        "successful_logins",
        "total_alerts",
    ]

    for field in required_fields:
        assert field in data
        assert isinstance(data[field], int)
        assert data[field] >= 0

    assert (
        data["failed_logins"] + data["successful_logins"]
        <= data["total_events"]
    )


# --------------------------------------------------
# TEST 5: UNKNOWN ENDPOINT
# --------------------------------------------------

def test_unknown_endpoint():
    response = client.get("/does-not-exist")

    assert response.status_code == 404


# --------------------------------------------------
# TEST 6: CONTROLLED SECURITY EVENT DATA
# --------------------------------------------------

def test_api_uses_controlled_sample_data(monkeypatch):

    sample_events = [
        {
            "event_id": 4625,
            "timestamp": "2026-10-24T12:00:00+00:00",
            "username": "test-user",
            "source_ip": "192.0.2.15",
            "hostname": "TEST-WIN10",
            "message": "Failed login",
        }
    ]

    sample_alerts = [
        {
            "rule_id": "SOC-001",
            "source_ip": "192.0.2.15",
            "severity": "medium",
            "status": "open",
        }
    ]

    # Replace database retrieval functions with controlled data.
    # This does not modify the SQLite database.

    monkeypatch.setattr(
        api_module,
        "get_all_events",
        lambda: sample_events,
    )

    monkeypatch.setattr(
        api_module,
        "get_all_alerts",
        lambda: sample_alerts,
    )

    # Verify event retrieval.
    events_response = client.get("/events")

    assert events_response.status_code == 200

    events_data = events_response.json()

    assert events_data["total"] == 1
    assert events_data["events"] == sample_events

    # Verify alert retrieval.
    alerts_response = client.get("/alerts")

    assert alerts_response.status_code == 200

    alerts_data = alerts_response.json()

    assert alerts_data["total"] == 1
    assert alerts_data["alerts"] == sample_alerts

    # Verify statistics.
    stats_response = client.get("/stats")

    assert stats_response.status_code == 200

    assert stats_response.json() == {
        "total_events": 1,
        "failed_logins": 1,
        "successful_logins": 0,
        "total_alerts": 1,
    }