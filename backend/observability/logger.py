"""
SOC//LAB Structured JSON Logging.

Provides consistent, machine-readable application logs.
"""

import json
import logging
import sys

from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Convert Python logging records into JSON."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(
                record.created,
                tz=timezone.utc,
            ).isoformat(),
            "level": record.levelname,
            "service": "soc-lab",
            "event": record.getMessage(),
        }

        if hasattr(record, "details"):
            log_entry.update(record.details)

        if record.exc_info:
            log_entry["exception"] = self.formatException(
                record.exc_info
            )

        return json.dumps(log_entry, default=str)


def get_logger(name="soc-lab"):
    """Create or retrieve a configured JSON logger."""

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

    return logger