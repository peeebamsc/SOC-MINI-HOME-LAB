"""
SOC//LAB Synthetic Authentication Event Simulator.

Generates synthetic Windows authentication events,
stores them in SQLite, evaluates SOC-001 and SOC-002
detections, and produces structured JSON logs.
"""

import argparse
import random
import time

from datetime import datetime, timezone, timedelta

from backend.models.security_event import SecurityEvent
from backend.detectors.failed_login import detect_failed_logins
from backend.detectors.successful_login import detect_success_after_failures
from backend.observability.logger import get_logger

from backend.storage.database import (
    initialize_database,
    save_events,
    save_alerts,
    get_all_events,
    get_all_alerts,
)


# --------------------------------------------------
# Structured Logging
# --------------------------------------------------

logger = get_logger("soc-lab.simulator")


# --------------------------------------------------
# Synthetic Event Configuration
# --------------------------------------------------

SOURCE_IPS = [
    "192.0.2.15",
    "192.0.2.20",
    "198.51.100.10",
    "203.0.113.25",
]

USERNAMES = [
    "analyst",
    "administrator",
    "test-user",
    "service-account",
]

HOSTNAMES = [
    "SOC-WIN10",
    "SOC-SERVER01",
    "SOC-WORKSTATION",
]


# --------------------------------------------------
# Event Generation
# --------------------------------------------------

def generate_event():
    """Generate one synthetic Windows authentication event."""

    event_id = random.choices(
        population=[4624, 4625],
        weights=[40, 60],
        k=1,
    )[0]

    message = (
        "An account failed to log on"
        if event_id == 4625
        else "An account was successfully logged on"
    )

    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        username=random.choice(USERNAMES),
        source_ip=random.choice(SOURCE_IPS),
        hostname=random.choice(HOSTNAMES),
        message=message,
    )


# --------------------------------------------------
# Detection Processing
# --------------------------------------------------

def process_detections(trigger_event=None):
    """
    Evaluate recent authentication events.

    When a triggering event is supplied, only alerts
    associated with that event are eligible for storage.

    Without a triggering event, preserve the existing
    full-window detection behavior.
    """

    stored_events = get_all_events()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=5)

    recent_events = []

    for event_data in stored_events:
        event = SecurityEvent.model_validate(event_data)

        if cutoff <= event.timestamp <= now:
            recent_events.append(event)

    soc001_alerts = detect_failed_logins(
        recent_events,
        threshold=3,
        window_minutes=5,
    )

    soc002_alerts = detect_success_after_failures(
        recent_events,
        threshold=3,
        window_minutes=5,
    )

    if trigger_event is not None:

        trigger_timestamp = trigger_event.timestamp.isoformat()

        if trigger_event.event_id == 4625:
            soc001_alerts = [
                alert
                for alert in soc001_alerts
                if (
                    alert["source_ip"] == trigger_event.source_ip
                    and alert["last_seen"] == trigger_timestamp
                )
            ]

            soc002_alerts = []

        elif trigger_event.event_id == 4624:
            soc002_alerts = [
                alert
                for alert in soc002_alerts
                if (
                    alert["source_ip"] == trigger_event.source_ip
                    and alert["username"] == trigger_event.username
                    and alert["last_seen"] == trigger_timestamp
                )
            ]

            soc001_alerts = []

        else:
            soc001_alerts = []
            soc002_alerts = []

    existing_alerts = get_all_alerts()

    previous_counts = {
        "SOC-001": sum(
            alert["rule_id"] == "SOC-001"
            for alert in existing_alerts
        ),
        "SOC-002": sum(
            alert["rule_id"] == "SOC-002"
            for alert in existing_alerts
        ),
    }

    save_alerts(soc001_alerts + soc002_alerts)

    stored_alerts = get_all_alerts()

    current_counts = {
        "SOC-001": sum(
            alert["rule_id"] == "SOC-001"
            for alert in stored_alerts
        ),
        "SOC-002": sum(
            alert["rule_id"] == "SOC-002"
            for alert in stored_alerts
        ),
    }

    return {
        rule_id: current_counts[rule_id] - previous_counts[rule_id]
        for rule_id in previous_counts
    }


# --------------------------------------------------
# Simulator Execution
# --------------------------------------------------

def run_simulator(interval=5, count=0):
    """Generate, store, analyze, and log synthetic events."""

    initialize_database()

    generated = 0
    new_alerts = 0

    print("\nSOC//LAB Synthetic Event Simulator")
    print("--------------------------------")
    print(f"Interval: {interval} seconds")
    print(f"Event limit: {count if count else 'continuous'}")
    print("Detection rules: SOC-001, SOC-002")
    print("Structured logging: enabled")
    print("Press Ctrl+C to stop.\n")

    try:
        while count == 0 or generated < count:

            # Generate synthetic event
            event = generate_event()

            # Persist event to SQLite
            save_events([event])

            # Log event ingestion
            logger.info(
                "security_event_ingested",
                extra={
                    "details": {
                        "event_id": event.event_id,
                        "username": event.username,
                        "source_ip": event.source_ip,
                        "hostname": event.hostname,
                    }
                },
            )

            generated += 1

            # Execute both detection rules
            detection_results = process_detections(trigger_event=event)

            alerts_created = sum(detection_results.values())

            # Log results separately for each detection rule
            for rule_id, rule_alert_count in detection_results.items():

                logger.info(
                    "detection_completed",
                    extra={
                        "details": {
                            "rule_id": rule_id,
                            "new_alerts": rule_alert_count,
                        }
                    },
                )

                if rule_alert_count > 0:
                    logger.info(
                        "security_alert_created",
                        extra={
                            "details": {
                                "rule_id": rule_id,
                                "new_alerts": rule_alert_count,
                        }
                    },
                )

            new_alerts += alerts_created

            # Preserve existing terminal output
            print(
                f"[{generated}] "
                f"Event={event.event_id} "
                f"User={event.username} "
                f"IP={event.source_ip} "
                f"NewAlerts={alerts_created}"
            )

            if count == 0 or generated < count:
                time.sleep(interval)

    except KeyboardInterrupt:
        print("\nSimulator stopped.")

    print("\nSimulation Summary")
    print("------------------")
    print(f"Events generated: {generated}")
    print(f"New alerts created: {new_alerts}")


# --------------------------------------------------
# Command-Line Interface
# --------------------------------------------------

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="SOC//LAB Synthetic Event Simulator"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=5,
        help="Seconds between events",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of events; 0 runs continuously",
    )

    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("--interval must be greater than zero")

    if args.count < 0:
        parser.error("--count cannot be negative")

    run_simulator(
        interval=args.interval,
        count=args.count,
    )