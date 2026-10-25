"""
SOC//LAB SQLite Storage Layer.

Handles database initialization, security event persistence,
alert persistence, and retrieval.
"""

import json
import os
import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "soc_lab.db"
)

DB_PATH = Path(
    os.environ.get("SOC_LAB_DB_PATH", str(DEFAULT_DB_PATH))
)


def get_connection():
    """Create a SQLite connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Initialize the security events and alerts tables."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                message TEXT NOT NULL,
                UNIQUE (
                    event_id,
                    timestamp,
                    username,
                    source_ip,
                    hostname,
                    message
                )
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                alert_data TEXT NOT NULL,
                UNIQUE (rule_id, source_ip, alert_data)
            )
            """
        )


def save_events(events):
    """Persist security events without inserting identical records."""
    with get_connection() as connection:
        for event in events:
            data = event.model_dump(mode="json")

            connection.execute(
                """
                INSERT OR IGNORE INTO security_events (
                    event_id,
                    timestamp,
                    username,
                    source_ip,
                    hostname,
                    message
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    data["event_id"],
                    data["timestamp"],
                    data["username"],
                    data["source_ip"],
                    data["hostname"],
                    data["message"],
                ),
            )


def save_alerts(alerts):
    """Persist security alerts without inserting identical records."""
    with get_connection() as connection:
        for alert in alerts:
            connection.execute(
                """
                INSERT OR IGNORE INTO security_alerts (
                    rule_id,
                    source_ip,
                    severity,
                    status,
                    alert_data
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    alert["rule_id"],
                    alert["source_ip"],
                    alert["severity"],
                    alert.get("status", "open"),
                    json.dumps(alert, sort_keys=True),
                ),
            )


def get_event_count():
    """Return the number of stored security events."""
    with get_connection() as connection:
        result = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()

        return result[0]


def get_alert_count():
    """Return the number of stored security alerts."""
    with get_connection() as connection:
        result = connection.execute(
            "SELECT COUNT(*) FROM security_alerts"
        ).fetchone()

        return result[0]


def get_all_events():
    """Retrieve security events ordered by newest timestamp."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                event_id,
                timestamp,
                username,
                source_ip,
                hostname,
                message
            FROM security_events
            ORDER BY timestamp DESC
            """
        ).fetchall()

        return [dict(row) for row in rows]


def get_all_alerts():
    """Retrieve stored security alerts, newest first."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT alert_data
            FROM security_alerts
            ORDER BY id DESC
            """
        ).fetchall()

        return [
            json.loads(row["alert_data"])
            for row in rows
        ]