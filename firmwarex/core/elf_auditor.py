"""Cross-architecture ELF metadata and binary hardening mitigation matrix auditor.

Evaluates:
- Architecture, Bitness, Endianness, ELF Type
- NX / DEP (PT_GNU_STACK permissions)
- RELRO (PT_GNU_RELRO + DT_BIND_NOW / DF_BIND_NOW -> Full vs Partial RELRO)
- PIE / ASLR (ET_DYN vs ET_EXEC)
- Stack Canaries (__stack_chk_fail presence)
- FORTIFY_SOURCE (__*_chk symbols)
- Suspicious imported sinks (strcpy, system, popen, sprintf, etc.) as review leads.

Uses evidence-based states: 'enabled', 'not_detected', 'unknown', 'not_applicable'.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


# Banned / dangerous C standard library functions flagged as triage leads
DANGEROUS_SINKS = {
    "strcpy": "Unbounded string copy (CWE-120)",
    "strcat": "Unbounded string concatenation (CWE-120)",
    "sprintf": "Format string buffer write without bound (CWE-120 / CWE-134)",
    "vsprintf": "Format string buffer write without bound (CWE-120 / CWE-134)",
    "gets": "Deprecated unbounded string input (CWE-120)",
    "scanf": "Potentially unbounded format read if %s is unconstrained (CWE-120)",
    "system": "Command execution with shell interpretation (CWE-78)",
    "popen": "Piped command execution with shell interpretation (CWE-78)",
}


@dataclass
class MitigationStatus:
    """Security mitigation assessment with explicit evidence status."""
    status: str  # 'enabled', 'not_detected', 'unknown', 'not_applicable'
    evidence: str
    details: Optional[str] = None


@dataclass
class BinaryAuditReport:
    """Full hardening audit and metadata report for a single ELF binary."""
    file_path: str
    is_valid_elf: bool
    architecture: str = "unknown"
    bitness: int = 0
    endianness: str = "unknown"
    elf_type: str = "unknown"
    is_stripped: bool = False
    is_static: bool = False
    nx: MitigationStatus = field(default_factory=lambda: MitigationStatus("unknown", "Not analysed"))
    pie: MitigationStatus = field(default_factory=lambda: MitigationStatus("unknown", "Not analysed"))
    relro: MitigationStatus = field(default_factory=lambda: MitigationStatus("unknown", "Not analysed"))
    canary: MitigationStatus = field(default_factory=lambda: MitigationStatus("unknown", "Not analysed"))
    fortify: MitigationStatus = field(default_factory=lambda: MitigationStatus("unknown", "Not analysed"))
    suspicious_sinks: List[Dict[str, str]] = field(default_factory=list)
    imported_symbols: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "is_valid_elf": self.is_valid_elf,
            "architecture": self.architecture,
            "bitness": self.bitness,
            "endianness": self.endianness,
            "elf_type": self.elf_type,
            "is_stripped": self.is_stripped,
            "is_static": self.is_static,
            "nx": asdict(self.nx),
            "pie": asdict(self.pie),
            "relro": asdict(self.relro),
            "canary": asdict(self.canary),
            "fortify": asdict(self.fortify),
            "suspicious_sinks": self.suspicious_sinks,
            "imported_symbols_count": len(self.imported_symbols),
            "error_message": self.error_message,
        }


class ELFAuditor:
    """Audits ELF binaries for compiler mitigations and risky function imports."""

    def __init__(self):
        if not PYELFTOOLS_AVAILABLE:
            # Fallback or warning if pyelftools not found
            pass

    def audit_binary(self, binary_path: Path, relative_display_path: Optional[str] = None) -> BinaryAuditReport:
        """Parse an ELF binary and inspect all security mitigations."""
        disp_path = relative_display_path or str(binary_path)

        if not binary_path.exists() or not binary_path.is_file():
            return BinaryAuditReport(
                file_path=disp_path,
                is_valid_elf=False,
                error_message="File does not exist or is not a regular file.",
            )

        # Quick magic check
        try:
            with open(binary_path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    return BinaryAuditReport(
                        file_path=disp_path,
                        is_valid_elf=False,
                        error_message="Not an ELF binary (missing 7F 45 4C 46 magic header).",
                    )
        except Exception as e:
            return BinaryAuditReport(
                file_path=disp_path,
                is_valid_elf=False,
                error_message=f"Read error: {str(e)}",
            )

        if not PYELFTOOLS_AVAILABLE:
            return self._fallback_manual_audit(binary_path, disp_path)

        try:
            with open(binary_path, "rb") as f:
                elf = ELFFile(f)
                return self._parse_with_pyelftools(elf, binary_path, disp_path)
        except Exception as e:
            return BinaryAuditReport(
                file_path=disp_path,
                is_valid_elf=True,
                error_message=f"ELF parsing exception: {str(e)}",
            )

    def _parse_with_pyelftools(self, elf: "ELFFile", binary_path: Path, disp_path: str) -> BinaryAuditReport:
        """Perform comprehensive inspection using pyelftools."""
        header = elf.header
        e_type = header.get("e_type", "unknown")
        e_machine = header.get("e_machine", "unknown")
        bitness = 64 if elf.elfclass == 64 else 32
        endianness = "little" if elf.little_endian else "big"

        # Normalize architecture label for IoT targets
        arch_norm = str(e_machine).replace("EM_", "")
        if "MIPS" in arch_norm.upper():
            architecture = "MIPSEL" if endianness == "little" else "MIPS"
        elif "ARM" in arch_norm.upper():
            architecture = "ARM64" if bitness == 64 else "ARM32"
        elif "AARCH64" in arch_norm.upper():
            architecture = "ARM64"
        elif "X86_64" in arch_norm.upper() or "AMD64" in arch_norm.upper():
            architecture = "x86_64"
        elif "386" in arch_norm or "86" in arch_norm:
            architecture = "x86"
        else:
            architecture = arch_norm

        # 1. NX (No-Execute) check via PT_GNU_STACK
        nx_status = MitigationStatus("not_detected", "PT_GNU_STACK segment not present in program headers.")
        has_gnu_stack = False
        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_GNU_STACK":
                has_gnu_stack = True
                # Check PF_X (0x1) flag
                flags = segment.header.p_flags
                if flags & 0x1:
                    nx_status = MitigationStatus(
                        status="not_detected",
                        evidence="PT_GNU_STACK header has execute flag enabled (PF_X). Stack is executable.",
                    )
                else:
                    nx_status = MitigationStatus(
                        status="enabled",
                        evidence="PT_GNU_STACK header present without PF_X flag. Non-executable stack enforced.",
                    )
                break

        if not has_gnu_stack:
            # Architecture-dependent default: on older MIPS or ARM, lack of PT_GNU_STACK often means executable stack
            nx_status = MitigationStatus(
                status="not_detected",
                evidence="PT_GNU_STACK segment absent. Binary defaults to executable stack or kernel policy.",
            )

        # 2. RELRO (Read-Only Relocations)
        has_gnu_relro = False
        for segment in elf.iter_segments():
            if segment.header.p_type == "PT_GNU_RELRO":
                has_gnu_relro = True
                break

        has_bind_now = False
        dynamic_sec = elf.get_section_by_name(".dynamic")
        if dynamic_sec:
            for tag in dynamic_sec.iter_tags():
                if tag.entry.d_tag in ("DT_BIND_NOW", "DF_BIND_NOW"):
                    has_bind_now = True
                    break
                if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):  # DF_BIND_NOW
                    has_bind_now = True
                    break

        if has_gnu_relro:
            if has_bind_now:
                relro_status = MitigationStatus(
                    status="enabled",
                    evidence="Full RELRO enabled (PT_GNU_RELRO and BIND_NOW flags active). GOT is completely read-only.",
                )
            else:
                relro_status = MitigationStatus(
                    status="enabled",
                    evidence="Partial RELRO enabled (PT_GNU_RELRO present, but BIND_NOW is absent).",
                    details="partial_relro",
                )
        else:
            relro_status = MitigationStatus(
                status="not_detected",
                evidence="No PT_GNU_RELRO segment found. Global Offset Table is fully writable.",
            )

        # 3. PIE (Position Independent Executable) / ASLR
        if e_type == "ET_DYN":
            # ET_DYN can be shared library (.so) or PIE executable
            # If dynamic section contains DT_DEBUG, typically a PIE executable
            has_dt_debug = False
            if dynamic_sec:
                for tag in dynamic_sec.iter_tags():
                    if tag.entry.d_tag == "DT_DEBUG":
                        has_dt_debug = True
                        break
            if has_dt_debug:
                pie_status = MitigationStatus(
                    status="enabled",
                    evidence="PIE executable detected (ET_DYN with DT_DEBUG tag). ASLR supported.",
                )
            else:
                pie_status = MitigationStatus(
                    status="enabled",
                    evidence="Position-independent code (ET_DYN / Shared object).",
                )
        elif e_type == "ET_EXEC":
            pie_status = MitigationStatus(
                status="not_detected",
                evidence="Standard executable without PIE (ET_EXEC). Base address is fixed.",
            )
        elif e_type == "ET_REL":
            pie_status = MitigationStatus(
                status="not_applicable",
                evidence="Relocatable object file (ET_REL). Mitigation applies at final link time.",
            )
        else:
            pie_status = MitigationStatus(
                status="unknown",
                evidence=f"Unknown or non-standard ELF type: {e_type}.",
            )

        # 4. Check Symbols (Canary, FORTIFY, Imports)
        all_symbols: Set[str] = set()
        is_stripped = True
        is_static = dynamic_sec is None

        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                if section.name == ".symtab":
                    is_stripped = False
                for symbol in section.iter_symbols():
                    if symbol.name:
                        all_symbols.add(symbol.name)

        # 5. Stack Canary (__stack_chk_fail)
        if any("__stack_chk_fail" in s or "__stack_chk_guard" in s for s in all_symbols):
            canary_status = MitigationStatus(
                status="enabled",
                evidence="Stack canary protection symbols detected (__stack_chk_fail/__stack_chk_guard).",
            )
        elif is_stripped and is_static:
            canary_status = MitigationStatus(
                status="unknown",
                evidence="Binary is stripped and statically linked. Canary status cannot be verified from symbols.",
            )
        else:
            canary_status = MitigationStatus(
                status="not_detected",
                evidence="No stack canary guard or failure handler symbols detected in symbol tables.",
            )

        # 6. FORTIFY_SOURCE (__*_chk symbols)
        fortified_symbols = [s for s in all_symbols if s.startswith("__") and s.endswith("_chk")]
        if fortified_symbols:
            fortify_status = MitigationStatus(
                status="enabled",
                evidence=f"Fortified functions detected ({len(fortified_symbols)} symbols: {', '.join(fortified_symbols[:3])}...).",
            )
        else:
            fortify_status = MitigationStatus(
                status="not_detected",
                evidence="No fortified (__*_chk) glibc wrappers detected.",
            )

        # 7. Suspicious Sinks (Review Leads)
        suspicious_sinks: List[Dict[str, str]] = []
        for symbol in sorted(all_symbols):
            clean_sym = symbol.strip()
            # Handle versioned symbols e.g. strcpy@GLIBC_2.0
            base_sym = clean_sym.split("@")[0]
            if base_sym in DANGEROUS_SINKS:
                suspicious_sinks.append({
                    "sink": base_sym,
                    "symbol": clean_sym,
                    "rationale": DANGEROUS_SINKS[base_sym],
                    "status": "review_lead",
                })

        return BinaryAuditReport(
            file_path=disp_path,
            is_valid_elf=True,
            architecture=architecture,
            bitness=bitness,
            endianness=endianness,
            elf_type=str(e_type),
            is_stripped=is_stripped,
            is_static=is_static,
            nx=nx_status,
            pie=pie_status,
            relro=relro_status,
            canary=canary_status,
            fortify=fortify_status,
            suspicious_sinks=suspicious_sinks,
            imported_symbols=sorted(list(all_symbols))[:100],  # Bounded sample
        )

    def _fallback_manual_audit(self, binary_path: Path, disp_path: str) -> BinaryAuditReport:
        """Minimal fallback parser if pyelftools is unavailable."""
        import struct
        with open(binary_path, "rb") as f:
            data = f.read(64)

        bitness = 32 if data[4] == 1 else (64 if data[4] == 2 else 0)
        is_little = data[5] == 1
        endianness = "little" if is_little else ("big" if data[5] == 2 else "unknown")
        
        # Read e_machine (bytes 18-19)
        e_machine = 0
        if len(data) >= 20:
            end_char = "<" if is_little else ">"
            e_machine = struct.unpack(f"{end_char}H", data[18:20])[0]

        arch_map = {3: "x86", 8: "MIPS", 40: "ARM32", 62: "x86_64", 183: "ARM64"}
        architecture = arch_map.get(e_machine, f"machine_{e_machine}")
        if architecture == "MIPS" and endianness == "little":
            architecture = "MIPSEL"

        return BinaryAuditReport(
            file_path=disp_path,
            is_valid_elf=True,
            architecture=architecture,
            bitness=bitness,
            endianness=endianness,
            elf_type="unknown",
            nx=MitigationStatus("unknown", "pyelftools library not installed for deep header analysis."),
            pie=MitigationStatus("unknown", "pyelftools library not installed."),
            relro=MitigationStatus("unknown", "pyelftools library not installed."),
            canary=MitigationStatus("unknown", "pyelftools library not installed."),
            fortify=MitigationStatus("unknown", "pyelftools library not installed."),
        )

    def audit_all_in_directory(self, extraction_dir: Path) -> List[BinaryAuditReport]:
        """Discover and audit all ELF binaries inside extraction_dir."""
        results: List[BinaryAuditReport] = []
        resolved_root = extraction_dir.resolve()

        for path in resolved_root.rglob("*"):
            if not path.is_file():
                continue
            # Quick magic check to avoid parsing non-ELFs
            try:
                with open(path, "rb") as f:
                    magic = f.read(4)
                    if magic == b"\x7fELF":
                        rel_path = path.relative_to(resolved_root).as_posix()
                        report = self.audit_binary(path, relative_display_path=rel_path)
                        results.append(report)
            except Exception:
                continue

        return results


def summarize_mitigations(reports: List[BinaryAuditReport]) -> Dict[str, Any]:
    """Compute aggregate counts and percentage metrics across audited binaries."""
    total = len(reports)
    if total == 0:
        return {
            "total_binaries": 0,
            "nx_enabled": 0,
            "pie_enabled": 0,
            "relro_full": 0,
            "relro_partial": 0,
            "canary_enabled": 0,
            "fortify_enabled": 0,
            "total_suspicious_sinks": 0,
        }

    nx_cnt = sum(1 for r in reports if r.nx.status == "enabled")
    pie_cnt = sum(1 for r in reports if r.pie.status == "enabled")
    relro_full = sum(1 for r in reports if r.relro.status == "enabled" and r.relro.details != "partial_relro")
    relro_partial = sum(1 for r in reports if r.relro.status == "enabled" and r.relro.details == "partial_relro")
    canary_cnt = sum(1 for r in reports if r.canary.status == "enabled")
    fortify_cnt = sum(1 for r in reports if r.fortify.status == "enabled")
    sink_cnt = sum(len(r.suspicious_sinks) for r in reports)

    return {
        "total_binaries": total,
        "nx_enabled": nx_cnt,
        "nx_percentage": round((nx_cnt / total) * 100, 1),
        "pie_enabled": pie_cnt,
        "pie_percentage": round((pie_cnt / total) * 100, 1),
        "relro_full": relro_full,
        "relro_partial": relro_partial,
        "canary_enabled": canary_cnt,
        "canary_percentage": round((canary_cnt / total) * 100, 1),
        "fortify_enabled": fortify_cnt,
        "fortify_percentage": round((fortify_cnt / total) * 100, 1),
        "total_suspicious_sinks": sink_cnt,
    }
