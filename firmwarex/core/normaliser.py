"""Finding normalization engine conforming to PRD Appendix A schema and CWE mapping."""

import uuid
from datetime import UTC, datetime
from typing import Any

from firmwarex.core.elf_auditor import BinaryAuditReport
from firmwarex.core.secret_scanner import SecretFinding


def current_rfc3339_utc() -> str:
    """Generate an ISO-8601 / RFC3339 UTC timestamp."""
    return datetime.now(UTC).isoformat()


class FindingNormaliser:
    """Transforms raw audit results and scanner outputs into validated Appendix A findings."""

    @staticmethod
    def from_secret_finding(finding: SecretFinding, firmware_id: str) -> dict[str, Any]:
        """Convert a SecretFinding into an Appendix A compliant dictionary with remediation guidance."""
        if finding.category == "hardcoded_secret":
            remediation = (
                "Remove plaintext credential from the firmware image. Store keys in a hardware secure element "
                "(e.g., TPM, Secure Enclave) or provision credentials dynamically via encrypted configuration at boot."
            )
        else:
            remediation = (
                "Replace legacy or weak cryptographic hashing (MD5/DES) with salted SHA-512 ($6$) with >=50,000 rounds, "
                "Argon2id, or yescrypt."
            )

        return {
            "vulnerability_id": str(uuid.uuid4()),
            "firmware_id": firmware_id,
            "binary": finding.file_path,
            "architecture": None,  # Not an ELF binary
            "category": finding.category,
            "cwe": finding.cwe,
            "address": None,
            "sink": None,
            "source": f"file:{finding.file_path}#L{finding.line_number}" if finding.line_number else f"file:{finding.file_path}",
            "tainted_path": [],
            "crash_state": {
                "fault_address": None,
                "registers": None,
                "overflow_offset": None,
                "stack_hash": None,
            },
            "risk_rating": finding.risk_rating,
            "confidence": finding.confidence,
            "evidence_ref": finding.evidence_ref,
            "redacted": finding.redacted,
            "remediation": remediation,
            "status": "new",
            "detected_at": current_rfc3339_utc(),
            "details": {
                "type": finding.finding_type,
                "preview": finding.redacted_preview,
                "description": finding.description,
            },
        }

    @staticmethod
    def from_binary_mitigations(audit: BinaryAuditReport, firmware_id: str) -> list[dict[str, Any]]:
        """Generate findings for missing binary mitigations and suspicious imported sinks."""
        findings: list[dict[str, Any]] = []

        # 1. Missing NX check
        if audit.nx.status == "not_detected":
            findings.append({
                "vulnerability_id": str(uuid.uuid4()),
                "firmware_id": firmware_id,
                "binary": audit.file_path,
                "architecture": audit.architecture,
                "category": "missing_mitigation",
                "cwe": "CWE-119",  # Memory safety weakness exacerbated by executable stack
                "address": None,
                "sink": None,
                "source": None,
                "tainted_path": [],
                "crash_state": {
                    "fault_address": None,
                    "registers": None,
                    "overflow_offset": None,
                    "stack_hash": None,
                },
                "risk_rating": "medium",
                "confidence": "probable",
                "evidence_ref": "elf:pt_gnu_stack_missing_or_executable",
                "redacted": False,
                "remediation": "Compile binary with '-z noexecstack'. Ensure target Linux kernel enforces non-executable memory protections (CONFIG_STRICT_DEVMEM / NX).",
                "status": "new",
                "detected_at": current_rfc3339_utc(),
                "details": {
                    "type": "Missing Stack Execution Protection (NX/DEP Disabled)",
                    "preview": audit.nx.evidence,
                    "description": "Binary lacks non-executable stack protection, facilitating arbitrary code execution via buffer overflow.",
                },
            })

        # 2. Missing PIE / ASLR
        if audit.pie.status == "not_detected":
            findings.append({
                "vulnerability_id": str(uuid.uuid4()),
                "firmware_id": firmware_id,
                "binary": audit.file_path,
                "architecture": audit.architecture,
                "category": "missing_mitigation",
                "cwe": "CWE-119",
                "address": None,
                "sink": None,
                "source": None,
                "tainted_path": [],
                "crash_state": {
                    "fault_address": None,
                    "registers": None,
                    "overflow_offset": None,
                    "stack_hash": None,
                },
                "risk_rating": "low",
                "confidence": "probable",
                "evidence_ref": "elf:pie_disabled",
                "redacted": False,
                "remediation": "Compile and link with '-fPIE -pie' to enable position-independent execution and maximize kernel ASLR entropy.",
                "status": "new",
                "detected_at": current_rfc3339_utc(),
                "details": {
                    "type": "Position-Independent Executable (PIE) Not Detected",
                    "preview": audit.pie.evidence,
                    "description": "Fixed base address execution limits the effectiveness of operating system ASLR.",
                },
            })

        # 3. Missing RELRO
        if audit.relro.status == "not_detected":
            findings.append({
                "vulnerability_id": str(uuid.uuid4()),
                "firmware_id": firmware_id,
                "binary": audit.file_path,
                "architecture": audit.architecture,
                "category": "missing_mitigation",
                "cwe": "CWE-119",
                "address": None,
                "sink": None,
                "source": None,
                "tainted_path": [],
                "crash_state": {
                    "fault_address": None,
                    "registers": None,
                    "overflow_offset": None,
                    "stack_hash": None,
                },
                "risk_rating": "low",
                "confidence": "probable",
                "evidence_ref": "elf:relro_disabled",
                "redacted": False,
                "remediation": "Compile with '-Wl,-z,relro,-z,now' (Full RELRO) to make the Global Offset Table read-only after dynamic linking.",
                "status": "new",
                "detected_at": current_rfc3339_utc(),
                "details": {
                    "type": "RELRO Disabled (Writable GOT)",
                    "preview": audit.relro.evidence,
                    "description": "Global Offset Table (GOT) remains writable, exposing control flow to hijacking.",
                },
            })

        # 4. Suspicious Imported Sinks (Review Leads, strictly marked as heuristic without invented crash state)
        for sink_info in audit.suspicious_sinks:
            sink_name = sink_info["sink"]
            is_cmd_inj = sink_name in ("system", "popen")
            category = "command_injection" if is_cmd_inj else "memory_corruption"
            cwe = "CWE-78" if is_cmd_inj else ("CWE-134" if "sprintf" in sink_name else "CWE-120")
            risk = "medium" if is_cmd_inj else "low"
            if is_cmd_inj:
                remediation = "Replace system() and popen() invocations with execve() or posix_spawn() passing discrete argument arrays, avoiding shell interpolation."
            else:
                remediation = "Replace unbounded libc string functions with safe alternatives (snprintf(), strlcpy(), or bounds-checked string abstractions) and enable FORTIFY_SOURCE (-D_FORTIFY_SOURCE=2)."

            findings.append({
                "vulnerability_id": str(uuid.uuid4()),
                "firmware_id": firmware_id,
                "binary": audit.file_path,
                "architecture": audit.architecture,
                "category": category,
                "cwe": cwe,
                "address": None,  # Static symbol import; call-site virtual address requires deep disassembly
                "sink": sink_name,
                "source": None,   # Static lead only; taint source requires dynamic/symbolic execution
                "tainted_path": [],
                "crash_state": {
                    "fault_address": None,
                    "registers": None,
                    "overflow_offset": None,
                    "stack_hash": None,
                },
                "risk_rating": risk,
                "confidence": "heuristic",
                "evidence_ref": f"symbol_import:{sink_info['symbol']}",
                "redacted": False,
                "remediation": remediation,
                "status": "new",
                "detected_at": current_rfc3339_utc(),
                "details": {
                    "type": f"Suspicious Banned Function Import ({sink_name})",
                    "preview": f"Imported symbol: {sink_info['symbol']} ({sink_info['rationale']})",
                    "description": "Binary imports a hazardous C standard library function. Triage lead for review; reachability from attacker input not proven.",
                },
            })

        return findings
