"""Finding normalization engine conforming to PRD Appendix A schema and CWE mapping."""

import uuid
from datetime import UTC, datetime
from typing import Any

from firmwarex.core.elf_auditor import BinaryAuditReport
from firmwarex.core.secret_scanner import SecretFinding
from firmwarex.core.symbolic_analyzer import SymbolicReviewLead


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


    @staticmethod
    def from_symbolic_lead(
        lead: SymbolicReviewLead, firmware_id: str, architecture: str | None = None
    ) -> dict[str, Any]:
        """Convert a SymbolicReviewLead into an Appendix A compliant finding."""
        is_cmd = lead.sink_symbol in ("system", "popen", "execl", "execve")
        if is_cmd:
            remediation = "Replace command execution with posix_spawn() or execve() using discrete argument arrays, avoiding shell interpolation."
        elif "sprintf" in lead.sink_symbol:
            remediation = "Replace sprintf with snprintf specifying maximum destination buffer size."
        else:
            remediation = "Replace unbounded memory copy with bounds-checked alternatives and enable compiler stack canaries."

        return {
            "vulnerability_id": str(uuid.uuid4()),
            "firmware_id": firmware_id,
            "binary": lead.binary_path,
            "architecture": architecture,
            "category": lead.category,
            "cwe": lead.cwe_id,
            "address": None,
            "sink": lead.sink_symbol,
            "source": lead.source_symbol,
            "tainted_path": lead.tainted_path or [lead.source_symbol, lead.sink_symbol],
            "crash_state": {
                "fault_address": None,
                "registers": None,
                "overflow_offset": None,
                "stack_hash": None,
            },
            "risk_rating": "medium" if is_cmd else "low",
            "confidence": lead.confidence,
            "evidence_ref": f"taint_path:{lead.source_symbol}->{lead.sink_symbol}",
            "redacted": False,
            "remediation": remediation,
            "status": "new",
            "detected_at": current_rfc3339_utc(),
            "details": {
                "type": f"Taint Reachability Lead: {lead.source_symbol} -> {lead.sink_symbol}",
                "preview": lead.evidence,
                "description": f"Potential data flow from input '{lead.source_symbol}' to dangerous sink '{lead.sink_symbol}'.",
                "reaching_condition": getattr(lead, "reaching_condition", None),
                "limitations": lead.limitations,
            },
        }

    @staticmethod
    def from_dynamic_crash(
        crash_rep: Any, firmware_id: str, binary: str, arch: str | None = None
    ) -> dict[str, Any]:
        """Convert a CrashReport or dictionary into an Appendix A compliant finding."""
        c = crash_rep if isinstance(crash_rep, dict) else crash_rep.to_dict()
        return {
            "vulnerability_id": str(uuid.uuid4()),
            "firmware_id": firmware_id,
            "binary": binary,
            "architecture": arch,
            "category": "dynamic_crash",
            "cwe": c.get("candidate_cwe", "CWE-119"),
            "address": c.get("fault_address"),
            "sink": c.get("signal"),
            "source": "dynamic_emulation",
            "tainted_path": [],
            "crash_state": {
                "fault_address": c.get("fault_address"),
                "registers": c.get("registers"),
                "overflow_offset": c.get("overflow_offset"),
                "stack_hash": c.get("stack_hash"),
            },
            "risk_rating": c.get("risk_rating", "high"),
            "confidence": c.get("confidence", "confirmed"),
            "evidence_ref": f"crash:{c.get('signal')}:{c.get('stack_hash')}",
            "redacted": False,
            "remediation": c.get("remediation", "Investigate process fault using debugger and ASan."),
            "status": "new",
            "detected_at": current_rfc3339_utc(),
            "details": {
                "type": f"Dynamic Process Crash ({c.get('signal')})",
                "preview": c.get("diagnostic_summary"),
                "description": c.get("diagnostic_summary"),
                "trace": c.get("trace", []),
            },
        }
