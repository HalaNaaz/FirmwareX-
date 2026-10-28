"""Local SQLite metadata and findings repository for FirmwareX."""

import json
import sqlite3
from pathlib import Path
from typing import Any

from firmwarex.config import DB_PATH, ensure_directories


class StorageManager:
    """Manages persistent SQLite storage for firmware metadata, audits, and findings."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        ensure_directories()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Firmware uploads table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS firmware (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    format TEXT NOT NULL,
                    is_supported BOOLEAN NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    extraction_dir TEXT,
                    error_message TEXT
                )
            """)

            # Analysis jobs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    firmware_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    error_message TEXT,
                    FOREIGN KEY (firmware_id) REFERENCES firmware(id)
                )
            """)

            # File inventory table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firmware_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT,
                    is_elf BOOLEAN NOT NULL,
                    is_executable BOOLEAN NOT NULL,
                    FOREIGN KEY (firmware_id) REFERENCES firmware(id)
                )
            """)

            # Binary audit table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS binary_audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firmware_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    architecture TEXT NOT NULL,
                    bitness INTEGER NOT NULL,
                    endianness TEXT NOT NULL,
                    elf_type TEXT NOT NULL,
                    nx_status TEXT NOT NULL,
                    pie_status TEXT NOT NULL,
                    relro_status TEXT NOT NULL,
                    canary_status TEXT NOT NULL,
                    fortify_status TEXT NOT NULL,
                    raw_report_json TEXT NOT NULL,
                    FOREIGN KEY (firmware_id) REFERENCES firmware(id)
                )
            """)

            # Findings table (Appendix A compliant)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    vulnerability_id TEXT PRIMARY KEY,
                    firmware_id TEXT NOT NULL,
                    binary TEXT NOT NULL,
                    architecture TEXT,
                    category TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    risk_rating TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    evidence_ref TEXT NOT NULL,
                    redacted BOOLEAN NOT NULL,
                    status TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    FOREIGN KEY (firmware_id) REFERENCES firmware(id)
                )
            """)
            conn.commit()

    def save_firmware(self, fw_data: dict[str, Any]):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT OR REPLACE INTO firmware (
                        id, filename, sha256, size_bytes, format, is_supported, status, created_at, extraction_dir, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    fw_data["id"],
                    fw_data["filename"],
                    fw_data["sha256"],
                    fw_data["size_bytes"],
                    fw_data["format"],
                    fw_data["is_supported"],
                    fw_data["status"],
                    fw_data["created_at"],
                    fw_data.get("extraction_dir"),
                    fw_data.get("error_message"),
                ))
        finally:
            conn.close()

    def get_firmware(self, firmware_id: str) -> dict[str, Any] | None:
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM firmware WHERE id = ?", (firmware_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list_firmwares(self) -> list[dict[str, Any]]:
        conn = self._get_connection()
        try:
            rows = conn.execute("SELECT * FROM firmware ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def save_job(self, job_data: dict[str, Any]):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT OR REPLACE INTO jobs (
                        job_id, firmware_id, status, progress, stage, created_at, updated_at, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    job_data["job_id"],
                    job_data["firmware_id"],
                    job_data["status"],
                    job_data["progress"],
                    job_data["stage"],
                    job_data["created_at"],
                    job_data["updated_at"],
                    job_data.get("error_message"),
                ))
        finally:
            conn.close()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def save_inventory(self, firmware_id: str, items: list[Any]):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM inventory WHERE firmware_id = ?", (firmware_id,))
                for item in items:
                    d = item.to_dict() if hasattr(item, "to_dict") else item
                    conn.execute("""
                        INSERT INTO inventory (firmware_id, path, type, size_bytes, sha256, is_elf, is_executable)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        firmware_id,
                        d["path"],
                        d["type"],
                        d["size"],
                        d.get("sha256"),
                        d.get("is_elf", False),
                        d.get("is_executable", False),
                    ))
        finally:
            conn.close()

    def get_inventory(self, firmware_id: str) -> list[dict[str, Any]]:
        conn = self._get_connection()
        try:
            rows = conn.execute("SELECT * FROM inventory WHERE firmware_id = ? ORDER BY path ASC", (firmware_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def save_binary_audits(self, firmware_id: str, audits: list[Any]):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM binary_audits WHERE firmware_id = ?", (firmware_id,))
                for audit in audits:
                    d = audit.to_dict() if hasattr(audit, "to_dict") else audit
                    conn.execute("""
                        INSERT INTO binary_audits (
                            firmware_id, file_path, architecture, bitness, endianness, elf_type,
                            nx_status, pie_status, relro_status, canary_status, fortify_status, raw_report_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        firmware_id,
                        d["file_path"],
                        d["architecture"],
                        d["bitness"],
                        d["endianness"],
                        d["elf_type"],
                        d["nx"]["status"],
                        d["pie"]["status"],
                        d["relro"]["status"],
                        d["canary"]["status"],
                        d["fortify"]["status"],
                        json.dumps(d),
                    ))
        finally:
            conn.close()

    def get_binary_audits(self, firmware_id: str) -> list[dict[str, Any]]:
        conn = self._get_connection()
        try:
            rows = conn.execute("SELECT * FROM binary_audits WHERE firmware_id = ? ORDER BY file_path ASC", (firmware_id,)).fetchall()
            return [json.loads(r["raw_report_json"]) for r in rows]
        finally:
            conn.close()

    def save_findings(self, firmware_id: str, findings: list[dict[str, Any]]):
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM findings WHERE firmware_id = ?", (firmware_id,))
                for f in findings:
                    conn.execute("""
                        INSERT INTO findings (
                            vulnerability_id, firmware_id, binary, architecture, category, cwe,
                            risk_rating, confidence, evidence_ref, redacted, status, detected_at, finding_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        f["vulnerability_id"],
                        firmware_id,
                        f["binary"],
                        f.get("architecture"),
                        f["category"],
                        f["cwe"],
                        f["risk_rating"],
                        f["confidence"],
                        f["evidence_ref"],
                        f["redacted"],
                        f["status"],
                        f["detected_at"],
                        json.dumps(f),
                    ))
        finally:
            conn.close()

    def get_findings(self, firmware_id: str) -> list[dict[str, Any]]:
        conn = self._get_connection()
        try:
            rows = conn.execute("SELECT * FROM findings WHERE firmware_id = ? ORDER BY risk_rating DESC", (firmware_id,)).fetchall()
            return [json.loads(r["finding_json"]) for r in rows]
        finally:
            conn.close()
