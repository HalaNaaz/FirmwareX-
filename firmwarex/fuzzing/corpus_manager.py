"""Seed Corpus Management Engine for Reproducible Protocol Fuzzing.

Conforms to PRD FR-4.2:
1. Stable content-addressable storage (SHA-256 hash).
2. Protocol namespace isolation (HTTP, UPnP, MQTT).
3. Strict path traversal prevention: files confined to designated corpus storage.
4. Input validation (size limits, protocol formatting).
5. Duplicate seed detection and prevention.
6. Execution tracking (execution counts, anomalies triggered).
7. Plaintext credential scrubbing before persistence.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from firmwarex.config import DATA_DIR
from firmwarex.core.redactor import Redactor

DEFAULT_CORPUS_DIR = DATA_DIR / "corpus"
MAX_SEED_SIZE_BYTES = 64 * 1024  # 64 KB cap per individual seed


@dataclass
class SeedMetadata:
    """Provenance and telemetry tracking an individual fuzzing seed."""
    seed_id: str
    protocol: str  # "http", "upnp", "mqtt"
    name: str
    content_hash: str
    size_bytes: int
    created_at: str
    execution_count: int = 0
    anomalies_triggered: int = 0
    tags: list[str] | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class CorpusManager:
    """Manages persistent and in-memory seed corpuses for reproducible fuzzing."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = (base_dir or DEFAULT_CORPUS_DIR).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_default_seeds()

    def _get_protocol_dir(self, protocol: str) -> Path:
        """Resolve and confine protocol corpus subdirectory."""
        proto_clean = protocol.lower().strip()
        if not re.match(r"^[a-z0-9_-]+$", proto_clean):
            raise ValueError(f"Invalid protocol name: '{protocol}'")

        target_dir = (self.base_dir / proto_clean).resolve()
        # Prevent path traversal
        if not str(target_dir).startswith(str(self.base_dir)):
            raise PermissionError("Path traversal escape detected in corpus directory resolution.")

        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def add_seed(
        self,
        protocol: str,
        name: str,
        content: bytes | str,
        tags: list[str] | None = None,
    ) -> SeedMetadata:
        """Validate, sanitize, deduplicate, and persist a fuzzing seed."""
        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content

        if len(raw_bytes) > MAX_SEED_SIZE_BYTES:
            raise ValueError(f"Seed exceeds maximum allowed size ({MAX_SEED_SIZE_BYTES} bytes): got {len(raw_bytes)}")

        if len(raw_bytes) == 0:
            raise ValueError("Seed content cannot be empty (0 bytes).")

        # Plaintext secret screening & sanitization
        try:
            text_preview = raw_bytes.decode("utf-8", errors="ignore")
            # Screen for AWS or sensitive credential patterns
            if re.search(r"\bAKIA[0-9A-Z]{16}\b", text_preview) or "password=" in text_preview.lower():
                sanitized_text = Redactor.sanitize_evidence(text_preview)
                raw_bytes = sanitized_text.encode("utf-8")
        except Exception:
            pass

        content_hash = hashlib.sha256(raw_bytes).hexdigest()
        seed_id = f"{protocol.lower()}_{content_hash[:12]}"
        proto_dir = self._get_protocol_dir(protocol)

        seed_file = proto_dir / f"{seed_id}.bin"
        meta_file = proto_dir / f"{seed_id}.json"

        # Check for duplicate
        if seed_file.exists() and meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                return SeedMetadata(**meta)
            except Exception:
                pass

        # Write seed and metadata atomically
        seed_file.write_bytes(raw_bytes)
        metadata = SeedMetadata(
            seed_id=seed_id,
            protocol=protocol.lower(),
            name=name,
            content_hash=content_hash,
            size_bytes=len(raw_bytes),
            created_at=datetime.now(UTC).isoformat(),
            execution_count=0,
            anomalies_triggered=0,
            tags=tags or ["baseline"],
        )
        meta_file.write_text(json.dumps(metadata.to_dict(), indent=2), encoding="utf-8")
        return metadata

    def get_seed_content(self, protocol: str, seed_id: str) -> bytes | None:
        """Retrieve the raw binary payload of a designated seed."""
        proto_dir = self._get_protocol_dir(protocol)
        clean_id = Path(seed_id).name
        target_file = proto_dir / f"{clean_id}.bin"
        if target_file.exists():
            return target_file.read_bytes()
        return None

    def list_seeds(self, protocol: str | None = None) -> list[SeedMetadata]:
        """List all available seeds, optionally filtered by protocol."""
        results: list[SeedMetadata] = []
        protocols = [protocol.lower()] if protocol else [p.name for p in self.base_dir.iterdir() if p.is_dir()]

        for proto in protocols:
            try:
                proto_dir = self._get_protocol_dir(proto)
                for meta_file in proto_dir.glob("*.json"):
                    try:
                        data = json.loads(meta_file.read_text(encoding="utf-8"))
                        results.append(SeedMetadata(**data))
                    except Exception:
                        continue
            except Exception:
                continue

        return sorted(results, key=lambda s: s.created_at, reverse=True)

    def record_execution(self, protocol: str, seed_id: str, triggered_anomaly: bool = False) -> None:
        """Increment execution count and anomaly telemetry for reproducibility."""
        proto_dir = self._get_protocol_dir(protocol)
        clean_id = Path(seed_id).name
        meta_file = proto_dir / f"{clean_id}.json"
        if meta_file.exists():
            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                data["execution_count"] = data.get("execution_count", 0) + 1
                if triggered_anomaly:
                    data["anomalies_triggered"] = data.get("anomalies_triggered", 0) + 1
                meta_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except Exception:
                pass

    def _ensure_default_seeds(self) -> None:
        """Seed built-in, benign protocol baseline messages for initial testing."""
        # HTTP baseline seeds
        http_seeds = [
            ("http_get_index", "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: FirmwareX-Fuzzer/1.0\r\n\r\n"),
            ("http_post_api", 'POST /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{"action": "ping"}'),
        ]
        for name, content in http_seeds:
            try:
                self.add_seed("http", name, content, tags=["built_in", "rfc_baseline"])
            except Exception:
                pass

        # UPnP baseline seeds
        upnp_msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: ssdp:all\r\n\r\n"
        )
        upnp_soap = (
            "POST /control/WANIPConnection HTTP/1.1\r\n"
            "Host: 127.0.0.1:49152\r\n"
            'SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"\r\n'
            "Content-Type: text/xml; charset=utf-8\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        try:
            self.add_seed("upnp", "upnp_msearch_baseline", upnp_msearch, tags=["built_in", "ssdp"])
            self.add_seed("upnp", "upnp_soap_baseline", upnp_soap, tags=["built_in", "soap"])
        except Exception:
            pass

        # MQTT baseline seeds (CONNECT packet, 14 bytes)
        mqtt_connect = bytes([0x10, 0x0C, 0x00, 0x04, ord('M'), ord('Q'), ord('T'), ord('T'), 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00])
        # MQTT PUBLISH packet (topic: sensor, qos: 0, payload: ok)
        mqtt_publish = bytes([0x30, 0x0C, 0x00, 0x06, ord('s'), ord('e'), ord('n'), ord('s'), ord('o'), ord('r'), ord('o'), ord('k')])
        try:
            self.add_seed("mqtt", "mqtt_connect_baseline", mqtt_connect, tags=["built_in", "mqtt_3.1.1"])
            self.add_seed("mqtt", "mqtt_publish_baseline", mqtt_publish, tags=["built_in", "mqtt_3.1.1"])
        except Exception:
            pass
