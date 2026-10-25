"""
SOC//LAB FastAPI Application.

Provides security events, alerts, statistics,
health monitoring, and structured API logging.
"""

import sqlite3
import time

from fastapi import FastAPI, HTTPException, Request

from backend.observability.logger import get_logger

from backend.storage.database import (
    get_all_events,
    get_all_alerts,
)


app = FastAPI(
    title="SOC//LAB API",
    description="Security Operations and Detection Engineering Platform",
    version="1.0.0",
)

logger = get_logger("soc-lab.api")


# --------------------------------------------------
# Structured API Request Logging
# --------------------------------------------------

@app.middleware("http")
async def log_api_requests(request: Request, call_next):
    """Log API requests with status codes and response times."""

    start_time = time.perf_counter()
    path = request.url.path

    try:
        response = await call_next(request)

    except Exception:
        duration_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2,
        )

        logger.exception(
            "api_request_failed",
            extra={
                "details": {
                    "method": request.method,
                    "path": path,
                    "status_code": 500,
                    "duration_ms": duration_ms,
                }
            },
        )

        raise

    duration_ms = round(
        (time.perf_counter() - start_time) * 1000,
        2,
    )

    # Exclude routine Docker health checks.
    if path != "/health":

        level = (
            "warning"
            if response.status_code >= 400
            else "info"
        )

        log_method = getattr(logger, level)

        log_method(
            "api_request_completed",
            extra={
                "details": {
                    "method": request.method,
                    "path": path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                }
            },
        )

    return response


# --------------------------------------------------
# Database Access
# --------------------------------------------------

def load_events():
    """Retrieve security events from SQLite."""

    try:
        return get_all_events()

    except sqlite3.Error as exc:
        logger.error(
            "api_database_error",
            extra={
                "details": {
                    "operation": "load_events",
                    "error_type": type(exc).__name__,
                }
            },
        )

        raise HTTPException(
            status_code=500,
            detail="Security events could not be retrieved",
        ) from exc


def load_alerts():
    """Retrieve security alerts from SQLite."""

    try:
        return get_all_alerts()

    except (sqlite3.Error, ValueError, TypeError) as exc:
        logger.error(
            "api_database_error",
            extra={
                "details": {
                    "operation": "load_alerts",
                    "error_type": type(exc).__name__,
                }
            },
        )

        raise HTTPException(
            status_code=500,
            detail="Security alerts could not be retrieved",
        ) from exc


# --------------------------------------------------
# Health Endpoint
# --------------------------------------------------

@app.get("/health")
def health():
    """Return API health status."""

    return {
        "status": "healthy",
        "service": "soc-lab-api",
        "version": "1.0.0",
    }


# --------------------------------------------------
# Security Events Endpoint
# --------------------------------------------------

@app.get("/events")
def get_events():
    """Return stored security events."""

    events = load_events()

    return {
        "total": len(events),
        "events": events,
    }


# --------------------------------------------------
# Security Alerts Endpoint
# --------------------------------------------------

@app.get("/alerts")
def get_alerts():
    """Return stored security alerts."""

    alerts = load_alerts()

    return {
        "total": len(alerts),
        "alerts": alerts,
    }


# --------------------------------------------------
# Statistics Endpoint
# --------------------------------------------------

@app.get("/stats")
def get_stats():
    """Return SOC//LAB security statistics."""

    events = load_events()
    alerts = load_alerts()

    return {
        "total_events": len(events),
        "failed_logins": sum(
            event["event_id"] == 4625
            for event in events
        ),
        "successful_logins": sum(
            event["event_id"] == 4624
            for event in events
        ),
        "total_alerts": len(alerts),
    }