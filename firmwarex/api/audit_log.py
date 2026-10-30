"""Append-only immutable audit log for FirmwareX job execution and safety tracking."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from firmwarex.config import AUDIT_LOG_PATH, ensure_directories


class AuditLogger:
    """Records security-critical events, job transitions, and safety boundary violations."""

    def __init__(self, log_path: Path = AUDIT_LOG_PATH):
        self.log_path = log_path
        ensure_directories()

    def record_event(self, event_type: str, details: dict[str, Any]):
        """Write an append-only JSON event record to disk."""
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "details": details,
        }
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except Exception:
            # Audit logging must not crash main application execution
            pass

    def get_events(self, event_type: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Read recent audit records, optionally filtered by event_type."""
        if not self.log_path.exists():
            return []
        events: list[dict[str, Any]] = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if event_type is None or record.get("event_type") == event_type:
                            events.append(record)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            return []
        return events[-limit:]


