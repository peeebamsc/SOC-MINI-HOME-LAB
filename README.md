# SOC MINI HOME LAB PRACTICE

### Security Operations Detection & Monitoring Lab

SOC-MINI LAB is a Python-based cybersecurity project that simulates Windows authentication events, detects suspicious login activity, and provides security event monitoring through a REST API and interactive dashboard.

The project demonstrates security detection engineering, Python automation, event processing, database persistence, automated testing, and containerized deployment.

## Features

* Synthetic Windows authentication event generation
* SOC-001: Repeated failed authentication detection
* SOC-002: Successful authentication following repeated failures
* Event-driven alert generation
* SQLite storage for security events and alerts
* FastAPI REST API
* Streamlit monitoring dashboard with automatic refresh
* Docker Compose deployment and container health checks
* Automated testing with pytest

## Technology Stack

| Component            | Technology     |
| -------------------- | -------------- |
| Programming language | Python 3.11    |
| API                  | FastAPI        |
| Dashboard            | Streamlit      |
| Database             | SQLite         |
| Data validation      | Pydantic       |
| Containerization     | Docker Compose |
| Testing              | pytest         |

## Detection Rules

### SOC-001 — Repeated Failed Authentication

Detects three failed Windows authentication events (Event ID 4625) originating from the same source IP within five minutes.

**Severity:** Medium

### SOC-002 — Successful Login After Repeated Failures

Detects a successful Windows authentication event (Event ID 4624) following at least three failed authentication attempts from the same source IP and username within five minutes.

**Severity:** High

## Architecture

```text
Synthetic Windows Authentication Events
                  |
                  v
           Event Simulator
                  |
                  v
             SQLite
                  |
                  v
          Detection Engine
             /       \
            v         v
         SOC-001    SOC-002
             \       /
              v     v
            Alerts
               |
               v
          FastAPI REST API
               |
               v
       Streamlit Dashboard
```

## Running SOC-MINI LAB

### Requirements

* Docker Desktop
* Docker Compose

### Start the application

From the project directory:

```bash
docker compose up -d --build
```

### Check container health

```bash
docker compose ps
```

### Access the application

| Service             | Local address                |
| ------------------- | ---------------------------- |
| Dashboard           | http://127.0.0.1:8502        |
| API documentation   | http://127.0.0.1:8010/docs   |
| API health          | http://127.0.0.1:8010/health |
| Security statistics | http://127.0.0.1:8010/stats  |
| Security events     | http://127.0.0.1:8010/events |
| Security alerts     | http://127.0.0.1:8010/alerts |

### Generate synthetic authentication events

```bash
python -m backend.simulator.event_simulator --interval 1 --count 10
```

Run this command from the project directory using a Python environment with the dependencies in `requirements.txt` installed.

### Run automated tests

```bash
python -m pytest tests -q
```

**Current verification:** 19 passing tests.

## Data Persistence

SOC-MINI LAB stores security events and alerts in a local SQLite database.

The Docker API service uses a bind mount to preserve database contents across container restarts.

Runtime databases and local development files are excluded from Git.

## Project Scope

SOC-MINI LAB is an educational cybersecurity engineering project using synthetic Windows authentication events.

It does not currently ingest live Windows Event Logs, provide enterprise authentication, or function as a production SIEM.

## Planned Enhancements

* Alert acknowledgment and resolution
* Analyst investigation notes
* Additional detection rules
* Improved incident correlation
* Enhanced monitoring and reporting

## Author

Prince E. Eyo

Cybersecurity | Server Infrastructure | Python Automation
