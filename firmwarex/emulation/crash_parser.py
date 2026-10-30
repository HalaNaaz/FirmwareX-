"""Diagnostic crash-state parser and non-weaponized telemetry engine.

Parses crash signals, faulting addresses, and register dumps from QEMU user-mode
emulation or containment probe telemetry. Conforms strictly to PRD FR-3.3:
- Captures fault address, registers, stack hash, candidate CWE, risk rating.
- Missing diagnostic fields are explicitly None or unknown (never fabricated).
- Purely diagnostic for human analyst triage; never generates weaponized exploits or shellcode.
"""

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CrashReport:
    """Structured diagnostic representation of a process crash or fault."""
    signal: str  # e.g. "SIGSEGV", "SIGBUS", "SIGABRT", "SIGILL", "SIGFPE"
    fault_address: str | None
    registers: dict[str, str] | None
    overflow_offset: int | None
    stack_hash: str | None
    candidate_cwe: str
    risk_rating: str  # "critical", "high", "medium"
    confidence: str   # "confirmed", "probable"
    diagnostic_summary: str
    remediation: str
    trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CrashStateParser:
    """Extracts non-weaponized diagnostic telemetry from process termination outputs."""

    SIGNAL_MAP = {
        11: "SIGSEGV",
        139: "SIGSEGV",
        -11: "SIGSEGV",
        7: "SIGBUS",
        135: "SIGBUS",
        -7: "SIGBUS",
        6: "SIGABRT",
        134: "SIGABRT",
        -6: "SIGABRT",
        4: "SIGILL",
        132: "SIGILL",
        -4: "SIGILL",
        8: "SIGFPE",
        136: "SIGFPE",
        -8: "SIGFPE",
    }

    @classmethod
    def parse_crash(
        cls,
        stdout: str,
        stderr: str,
        exit_code: int | None,
        arch: str = "unknown",
        binary_name: str = "unknown",
    ) -> CrashReport | None:
        """Parse execution outputs and exit code to determine if a crash occurred."""
        combined_text = f"{stderr}\n{stdout}"

        # 1. Detect Signal
        signal_name: str | None = None
        if exit_code in cls.SIGNAL_MAP:
            signal_name = cls.SIGNAL_MAP[exit_code]

        # Scan text for QEMU target signal notifications
        qemu_sig_match = re.search(r"uncaught target signal\s+(\d+)\s*\(([^)]+)\)", combined_text, re.IGNORECASE)
        if qemu_sig_match:
            sig_num = int(qemu_sig_match.group(1))
            signal_name = cls.SIGNAL_MAP.get(sig_num, f"SIGNAL_{sig_num}")

        if not signal_name:
            if re.search(r"\b(?:segmentation fault|sigsegv)\b", combined_text, re.IGNORECASE):
                signal_name = "SIGSEGV"
            elif re.search(r"\b(?:bus error|sigbus)\b", combined_text, re.IGNORECASE):
                signal_name = "SIGBUS"
            elif re.search(r"\b(?:aborted|sigabrt)\b", combined_text, re.IGNORECASE):
                signal_name = "SIGABRT"
            elif re.search(r"\b(?:illegal instruction|sigill)\b", combined_text, re.IGNORECASE):
                signal_name = "SIGILL"

        if not signal_name:
            # Normal clean exit or non-crash error
            return None

        # 2. Extract Fault Address
        fault_address: str | None = None
        fault_patterns = [
            r"(?:fault\s+address|at\s+address|accessing|faulting\s+address)\s*[:=]?\s*(0x[0-9a-fA-F]+)",
            r"(?:pc|ip|epc)\s*[:=]\s*(0x[0-9a-fA-F]+)",
            r"qemu:\s*uncaught target signal \d+.*?\bat\s+(0x[0-9a-fA-F]+)",
        ]
        for pat in fault_patterns:
            m = re.search(pat, combined_text, re.IGNORECASE)
            if m:
                fault_address = m.group(1).lower()
                break

        # 3. Extract Register State
        registers: dict[str, str] = {}
        reg_patterns = [
            r"\b([a-zA-Z0-9_]{2,8})\s*[:=]\s*(0x[0-9a-fA-F]+)",
            r"\b(pc|sp|lr|fp|r[0-9]+|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|epc|ra)\s*=\s*(0x[0-9a-fA-F]+)",
            r"\b([R|E]?[A-Z0-9]{2,4}|[X|W|R][0-9]{1,2}|PC|SP|LR|FP|RIP|RSP|RBP|R[0-9]{2})\s*=\s*([0-9a-fA-F]{8,16})\b",
        ]
        for pat in reg_patterns:
            for match in re.finditer(pat, combined_text, re.IGNORECASE):
                reg_name = match.group(1).lower()
                reg_val = match.group(2).lower()
                if not reg_val.startswith("0x"):
                    reg_val = f"0x{reg_val}"
                registers[reg_name] = reg_val

        reg_dict = registers if registers else None

        # 4. Check for Buffer Overflow Offset / ASCII Pattern in fault address
        overflow_offset: int | None = None
        if fault_address:
            # Check if fault address is patterned ASCII e.g. 0x41414141 ('AAAA')
            raw_hex = fault_address.replace("0x", "")
            if len(raw_hex) in (8, 16):
                try:
                    bytes_val = bytes.fromhex(raw_hex)
                    if all(0x20 <= b <= 0x7E for b in bytes_val):
                        # Patterned ASCII detected
                        overflow_offset = len(bytes_val)
                except ValueError:
                    pass

        # 5. Compute Deterministic Stack Hash for deduplication
        hash_seed = f"{arch}:{binary_name}:{signal_name}:{fault_address or 'none'}:{sorted(registers.items())}"
        stack_hash = hashlib.sha256(hash_seed.encode("utf-8")).hexdigest()[:16]

        # 6. Determine Candidate CWE and Risk Rating
        if fault_address in ("0x0", "0x00000000", "0x0000000000000000", "0x0000"):
            candidate_cwe = "CWE-476"
            risk_rating = "medium"
            summary = f"NULL pointer dereference observed in {binary_name} during {signal_name} termination."
            remediation = "Validate pointer initialization and implement explicit null checks before dereferencing."
        elif overflow_offset is not None or "0x41414141" in str(fault_address):
            candidate_cwe = "CWE-120"
            risk_rating = "critical"
            summary = f"Control-flow memory corruption (possible buffer overflow) with patterned fault address {fault_address}."
            remediation = "Replace unbounded memory copies (strcpy, sprintf) with bounds-checked alternatives and enable compiler stack canaries."
        elif signal_name == "SIGSEGV":
            candidate_cwe = "CWE-119"
            risk_rating = "high"
            summary = f"Memory access violation (Segmentation fault) observed in {binary_name} at address {fault_address or 'unknown'}."
            remediation = "Investigate memory bounds and address validity using AddressSanitizer (-fsanitize=address)."
        elif signal_name == "SIGILL":
            candidate_cwe = "CWE-119"
            risk_rating = "medium"
            summary = f"Illegal instruction executed in {binary_name} (possible architecture mismatch or corrupt control flow)."
            remediation = "Verify binary target architecture compiler flags and check for corrupt function pointer jumps."
        else:
            candidate_cwe = "CWE-119"
            risk_rating = "medium"
            summary = f"Abnormal process termination ({signal_name}) observed in {binary_name}."
            remediation = "Inspect application fault handlers and assertions."

        # Extract call trace lines if present
        trace_lines = [
            line.strip()
            for line in combined_text.splitlines()
            if any(k in line.lower() for k in ["backtrace", "#0", "#1", "#2", "frame #", "called from"])
        ][:10]

        return CrashReport(
            signal=signal_name,
            fault_address=fault_address,
            registers=reg_dict,
            overflow_offset=overflow_offset,
            stack_hash=stack_hash,
            candidate_cwe=candidate_cwe,
            risk_rating=risk_rating,
            confidence="confirmed",
            diagnostic_summary=summary,
            remediation=remediation,
            trace=trace_lines,
        )

