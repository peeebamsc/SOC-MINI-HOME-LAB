"""
SOC//LAB Deterministic Authentication Attack Scenario.

Simulates three failed Windows login attempts
followed by one successful authentication.

All data is synthetic.
"""

from datetime import datetime, timedelta, timezone

from backend.models.security_event import SecurityEvent
from backend.storage.database import (
    initialize_database,
    save_events,
)
from backend.simulator.event_simulator import process_detections


def run_attack_scenario():
    """Generate a controlled authentication attack sequence."""

    initialize_database()

    base_time = datetime.now(timezone.utc) - timedelta(seconds=10)

    source_ip = "203.0.113.99"
    username = "soc-demo-user"

    print("\nSOC//LAB Controlled Attack Simulation")
    print("------------------------------------")

    event_ids = [4625, 4625, 4625, 4624]

    for index, event_id in enumerate(event_ids):

        event = SecurityEvent(
            event_id=event_id,
            timestamp=base_time + timedelta(seconds=index),
            username=username,
            source_ip=source_ip,
            hostname="SOC-DEMO-WIN10",
            message=(
                "An account failed to log on"
                if event_id == 4625
                else "An account was successfully logged on"
            ),
        )

        save_events([event])

        results = process_detections(trigger_event=event)

        print(
            f"Event={event_id} "
            f"User={username} "
            f"IP={source_ip} "
            f"SOC-001={results['SOC-001']} "
            f"SOC-002={results['SOC-002']}"
        )

    print("\nControlled attack simulation completed.")


if __name__ == "__main__":
    run_attack_scenario()