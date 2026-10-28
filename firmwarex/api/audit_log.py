"""Append-only immutable audit log for FirmwareX job execution and safety tracking."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from firmwarex.config import AUDIT_LOG_PATH, ensure_directories


class AuditLogger:
    """Records security-critical events, job transitions, and safety boundary violations."""

    def __init__(self, log_path: Path = AUDIT_LOG_PATH):
        self.log_path = log_path
        ensure_directories()

    def record_event(self, event_type: str, details: Dict[str, Any]):
        """Write an append-only JSON event record to disk."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "details": details,
        }
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except Exception:
            # Audit logging must not crash main application execution
            pass
