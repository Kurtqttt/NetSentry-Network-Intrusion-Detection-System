
import json
from datetime import datetime, timezone
from pathlib import Path

INCIDENT_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "incidents.json"
)


def load_incidents():
    if not INCIDENT_FILE.exists():
        return {}
    try:
        with INCIDENT_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return {}


def save_incidents(incidents):
    INCIDENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_file = INCIDENT_FILE.with_suffix(".tmp")
    with temp_file.open("w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=2)
    temp_file.replace(INCIDENT_FILE)


def alert_id(alert):
    parts = [
        str(alert.get("rule_id", "")),
        str(alert.get("source", "")),
        str(alert.get("destination", "")),
        str(alert.get("evidence", "")),
    ]
    return "|".join(parts)


def update_incident(alert, status, notes):
    incidents = load_incidents()
    key = alert_id(alert)
    existing = incidents.get(key, {})

    incidents[key] = {
        "rule_id": alert.get("rule_id", ""),
        "alert": alert.get("alert", ""),
        "severity": alert.get("severity", ""),
        "source": alert.get("source", ""),
        "destination": alert.get("destination", ""),
        "evidence": alert.get("evidence", ""),
        "status": status,
        "notes": notes,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "created_at": existing.get(
            "created_at", datetime.now(timezone.utc).isoformat()
        ),
    }
    save_incidents(incidents)


def export_incidents():
    return list(load_incidents().values())