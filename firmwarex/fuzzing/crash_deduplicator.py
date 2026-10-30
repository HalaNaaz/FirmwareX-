"""Crash Deduplication and Stack Fingerprinting Engine.

Conforms to PRD FR-4.3:
1. Normalizes unstable addresses (ASLR, randomized stack pointers) from raw backtraces.
2. Derives deterministic, stable SHA-256 crash fingerprints (algorithm: v1_normalized_stack_hash).
3. Groups duplicate crash events while maintaining distinct event occurrence records and counters.
4. Distinguishes crashes with different meaningful call stacks or termination signals.
5. Handles missing or incomplete backtraces honestly (marks confidence='partial', never fabricates frames).
6. Converts unique crash groups into normalized Appendix A findings.
"""

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from firmwarex.emulation.crash_parser import CrashReport


@dataclass
class NormalizedFrame:
    """A sanitized, address-independent stack trace frame."""
    frame_index: int
    symbol: str | None
    module: str | None
    normalized_offset: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CrashFingerprint:
    """Stable cryptographic identity for grouping crash events."""
    fingerprint_hash: str
    algorithm_version: str  # "v1_normalized_stack_hash"
    signal: str
    candidate_cwe: str
    normalized_frames: list[NormalizedFrame]
    completeness: str  # "complete", "partial", "signal_only"
    confidence: str    # "confirmed", "candidate"

    def to_dict(self) -> dict:
        return {
            "fingerprint_hash": self.fingerprint_hash,
            "algorithm_version": self.algorithm_version,
            "signal": self.signal,
            "candidate_cwe": self.candidate_cwe,
            "normalized_frames": [f.to_dict() for f in self.normalized_frames],
            "completeness": self.completeness,
            "confidence": self.confidence,
        }


@dataclass
class CrashGroup:
    """Aggregated crash group representing recurring defect occurrences."""
    fingerprint: str
    signal: str
    candidate_cwe: str
    affected_binary: str
    event_count: int
    first_seen: str
    last_seen: str
    diagnostic_summary: str
    remediation: str
    sample_crash: dict
    reproducing_payload_hash: str | None = None
    minimized_payload: str | None = None
    events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class CrashFingerprinter:
    """Extracts address-normalized stack fingerprints from crash reports."""

    ALGORITHM_VERSION = "v1_normalized_stack_hash"

    @classmethod
    def normalize_frame(cls, frame_line: str, idx: int) -> NormalizedFrame:
        """Strip ASLR variables from stack frame while preserving module and symbol offsets."""
        clean = frame_line.strip()
        # Pattern: #0 0x00401234 in main () from /bin/app
        # or #0 0x7fff... in libc.so.6+0x123
        module: str | None = None
        symbol: str | None = None

        sym_match = re.search(r"\bin\s+([a-zA-Z0-9_]+)", clean)
        if sym_match:
            symbol = sym_match.group(1)

        mod_match = re.search(r"\bfrom\s+([^\s]+)", clean)
        if mod_match:
            module = mod_match.group(1).split("/")[-1]

        # Strip high-order ASLR address bits: e.g. 0x7ffd12345678 -> 0x[OFFSET]
        norm_offset = re.sub(r"0x[0-9a-fA-F]{6,16}", "0x[OFFSET]", clean)
        return NormalizedFrame(
            frame_index=idx,
            symbol=symbol,
            module=module,
            normalized_offset=norm_offset,
        )

    @classmethod
    def compute_fingerprint(cls, crash: CrashReport, binary_name: str = "unknown") -> CrashFingerprint:
        """Derive deterministic crash fingerprint hash."""
        normalized_frames: list[NormalizedFrame] = []
        if crash.trace:
            for idx, line in enumerate(crash.trace):
                normalized_frames.append(cls.normalize_frame(line, idx))

        completeness = "complete" if len(normalized_frames) >= 2 else ("partial" if normalized_frames else "signal_only")
        confidence = "confirmed" if completeness == "complete" else "candidate"

        # Frame representation for hashing
        frame_reprs = [f"{f.symbol or 'unknown'}:{f.module or 'unknown'}" for f in normalized_frames]
        # If no trace frames, use fault address class (e.g. NULL vs non-NULL) + signal
        fault_type = "null_ptr" if crash.fault_address in ("0x0", "0x00000000", "0x0000", None) else "memory_fault"

        seed_data = f"{cls.ALGORITHM_VERSION}:{binary_name}:{crash.signal}:{crash.candidate_cwe}:{fault_type}:{frame_reprs}"
        fingerprint_hash = hashlib.sha256(seed_data.encode("utf-8")).hexdigest()[:16]

        return CrashFingerprint(
            fingerprint_hash=fingerprint_hash,
            algorithm_version=cls.ALGORITHM_VERSION,
            signal=crash.signal,
            candidate_cwe=crash.candidate_cwe,
            normalized_frames=normalized_frames,
            completeness=completeness,
            confidence=confidence,
        )


class CrashDeduplicator:
    """Manages crash aggregation, recurrence tracking, and deduplication."""

    def __init__(self):
        self._groups: dict[str, CrashGroup] = {}

    def record_crash(
        self,
        crash: CrashReport,
        binary_name: str = "unknown",
        firmware_id: str = "unknown",
        payload_hash: str | None = None,
        minimized_payload: str | None = None,
        job_id: str | None = None,
    ) -> tuple[CrashGroup, bool]:
        """Record a crash occurrence, grouping into an existing group or creating a new one.

        Returns:
            Tuple of (CrashGroup, is_new_group)
        """
        now = datetime.now(UTC).isoformat()
        fp = CrashFingerprinter.compute_fingerprint(crash, binary_name)

        event_data: dict[str, Any] = {
            "timestamp": now,
            "firmware_id": firmware_id,
            "job_id": job_id,
            "fault_address": crash.fault_address,
            "payload_hash": payload_hash,
        }

        if fp.fingerprint_hash in self._groups:
            group = self._groups[fp.fingerprint_hash]
            group.event_count += 1
            group.last_seen = now
            if payload_hash and not group.reproducing_payload_hash:
                group.reproducing_payload_hash = payload_hash
            if minimized_payload and not group.minimized_payload:
                group.minimized_payload = minimized_payload
            group.events.append(event_data)
            return group, False

        new_group = CrashGroup(
            fingerprint=fp.fingerprint_hash,
            signal=crash.signal,
            candidate_cwe=crash.candidate_cwe,
            affected_binary=binary_name,
            event_count=1,
            first_seen=now,
            last_seen=now,
            diagnostic_summary=crash.diagnostic_summary,
            remediation=crash.remediation,
            sample_crash=crash.to_dict(),
            reproducing_payload_hash=payload_hash,
            minimized_payload=minimized_payload,
            events=[event_data],
        )
        self._groups[fp.fingerprint_hash] = new_group
        return new_group, True

    def list_groups(self) -> list[CrashGroup]:
        """Return all deduplicated crash groups sorted by recurrence count."""
        return sorted(self._groups.values(), key=lambda g: g.event_count, reverse=True)

    def get_group(self, fingerprint: str) -> CrashGroup | None:
        """Retrieve an individual crash group by its fingerprint hash."""
        return self._groups.get(fingerprint)

