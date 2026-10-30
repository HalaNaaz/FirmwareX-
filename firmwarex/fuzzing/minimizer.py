"""Crash-Input Minimization Engine for Protocol and Dynamic Anomaly Reproduction.

Conforms to PRD FR-4.2:
1. Minimizes ONLY inputs associated with an observed crash or qualifying defect.
2. Preserves original input bytes and records cryptographic hash before/after.
3. Applies bounded delta-debugging (chunk removal, line removal, binary bisection).
4. Verifies reproduction equivalence against target verifier function.
5. Strictly bounds iterations and execution time to prevent runaway loops.
6. Returns structured telemetry with reduction ratio and reproduction confidence.
"""

import hashlib
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass


@dataclass
class MinimizationResult:
    """Telemetry report summarizing the outcome of bounded input minimization."""
    status: str  # "minimized", "reproduced_unreduced", "not_reproducible", "timed_out", "failed"
    original_size: int
    minimized_size: int
    reduction_percentage: float
    iterations: int
    duration_ms: float
    original_hash: str
    minimized_hash: str
    minimized_payload: bytes | str
    reproduced: bool

    def to_dict(self) -> dict:
        d = asdict(self)
        if isinstance(self.minimized_payload, bytes):
            d["minimized_payload"] = self.minimized_payload.decode("utf-8", errors="replace")
        return d


class CrashInputMinimizer:
    """Executes bounded delta-debugging to reduce crashing payloads while preserving defect reproduction."""

    def __init__(self, max_iterations: int = 50, timeout_seconds: float = 5.0, min_payload_size: int = 4):
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds
        self.min_payload_size = min_payload_size

    def minimize(
        self,
        payload: bytes | str,
        reproduction_verifier: Callable[[bytes], bool],
    ) -> MinimizationResult:
        """Attempt to reduce payload size while ensuring reproduction_verifier returns True.

        Args:
            payload: The original crashing input.
            reproduction_verifier: A callable taking candidate bytes and returning True
                                   if the crash/anomaly reproduces identically.

        Returns:
            MinimizationResult with reduction telemetry.
        """
        start_time = time.time()
        raw_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
        orig_hash = hashlib.sha256(raw_bytes).hexdigest()
        orig_len = len(raw_bytes)

        # Baseline verification: Confirm crash reproduces with original input
        try:
            initial_reproduction = reproduction_verifier(raw_bytes)
        except Exception:
            initial_reproduction = False

        if not initial_reproduction:
            return MinimizationResult(
                status="not_reproducible",
                original_size=orig_len,
                minimized_size=orig_len,
                reduction_percentage=0.0,
                iterations=1,
                duration_ms=round((time.time() - start_time) * 1000, 2),
                original_hash=orig_hash,
                minimized_hash=orig_hash,
                minimized_payload=raw_bytes,
                reproduced=False,
            )

        current = bytearray(raw_bytes)
        iterations = 1

        # Phase 1: Line/Chunk Removal (for protocol text streams)
        lines = bytes(current).split(b"\n")
        if len(lines) > 2:
            idx = 0
            while idx < len(lines) and iterations < self.max_iterations:
                if (time.time() - start_time) > self.timeout_seconds:
                    break
                candidate_lines = lines[:idx] + lines[idx + 1:]
                candidate_bytes = b"\n".join(candidate_lines)

                iterations += 1
                if len(candidate_bytes) >= self.min_payload_size and reproduction_verifier(candidate_bytes):
                    lines = candidate_lines
                    current = bytearray(candidate_bytes)
                else:
                    idx += 1

        # Phase 2: Binary Bisection / Block Deletion
        block_size = max(1, len(current) // 4)
        while block_size >= 1 and iterations < self.max_iterations and len(current) > self.min_payload_size:
            if (time.time() - start_time) > self.timeout_seconds:
                break

            improved = False
            for offset in range(0, len(current), block_size):
                if iterations >= self.max_iterations or (time.time() - start_time) > self.timeout_seconds:
                    break

                candidate = current[:offset] + current[offset + block_size:]
                if len(candidate) < self.min_payload_size:
                    continue

                iterations += 1
                try:
                    if reproduction_verifier(bytes(candidate)):
                        current = candidate
                        improved = True
                        break
                except Exception:
                    continue

            if not improved:
                block_size //= 2

        minimized_bytes = bytes(current)
        min_len = len(minimized_bytes)
        min_hash = hashlib.sha256(minimized_bytes).hexdigest()
        duration = round((time.time() - start_time) * 1000, 2)
        reduction = round(((orig_len - min_len) / orig_len) * 100, 2) if orig_len > 0 else 0.0

        if min_len < orig_len:
            status = "minimized"
        elif (time.time() - start_time) >= self.timeout_seconds:
            status = "timed_out"
        else:
            status = "reproduced_unreduced"

        return MinimizationResult(
            status=status,
            original_size=orig_len,
            minimized_size=min_len,
            reduction_percentage=reduction,
            iterations=iterations,
            duration_ms=duration,
            original_hash=orig_hash,
            minimized_hash=min_hash,
            minimized_payload=minimized_bytes,
            reproduced=True,
        )

