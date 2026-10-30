"""Tests for Priority 1, Phase 2: Safe Dynamic Analysis Engine & Execution Containment.

Covers:
- SC-1.1 to SC-1.3, SC-2.1 to SC-2.2: Sandbox containment, network denial, mount limits, cleanup
- FR-2.1: QEMU architecture mapping, input validation, tool discovery, containment gating
- FR-3.1, FR-3.4: Bounded symbolic analysis, Python 3.14 blocker reporting, budget exhaustion
- FR-3.2: Taint-to-sink data flow with modeled sources and sinks
- FR-3.3: Non-weaponized diagnostic crash-state reporting
- SC-3.1, SC-3.2: Secret detection, salted fingerprinting, non-reversible redaction
- PRD Appendix A: Finding normalization schema compliance
"""

from pathlib import Path

import pytest

from firmwarex.core.normaliser import FindingNormaliser
from firmwarex.core.redactor import Redactor
from firmwarex.core.secret_scanner import SecretScanner
from firmwarex.core.symbolic_analyzer import (
    ANGR_AVAILABLE,
    BoundedSymbolicAnalyzer,
    SymbolicBudget,
    SymbolicReviewLead,
)
from firmwarex.emulation.crash_parser import CrashReport, CrashStateParser
from firmwarex.emulation.qemu_adapter import (
    QemuArchitectureMapper,
    QemuEmulationAdapter,
    QemuToolDiscovery,
)
from firmwarex.isolation.sandbox_manager import (
    SANDBOX_BASE_DIR,
    ContainmentPreflight,
    DisposableSandbox,
)
from tests.fixtures_helper import create_minimal_elf


class TestSandboxContainment:
    """SC-1.1–1.3, SC-2.1–2.2: Sandbox isolation, path validation, and resource controls."""

    def test_preflight_verifies_or_fails_closed(self):
        """Containment preflight must return a structured result and never crash."""
        preflight = ContainmentPreflight.run_preflight()
        assert isinstance(preflight.passed, bool)
        assert isinstance(preflight.docker_available, bool)
        assert isinstance(preflight.diagnostics, list)
        if not preflight.docker_available:
            assert preflight.passed is False
            assert any("Docker CLI" in d or "FAIL-CLOSED" in d for d in preflight.diagnostics)

    def test_mount_path_validation_blocks_host_paths(self, tmp_path: Path):
        """Disallow mounting root drives, Windows system folders, docker socket, home dirs."""
        assert ContainmentPreflight.validate_mount_path(SANDBOX_BASE_DIR / "valid_id") is True
        assert ContainmentPreflight.validate_mount_path(Path("C:/Windows/System32")) is False
        assert ContainmentPreflight.validate_mount_path(Path("C:/Users")) is False
        assert ContainmentPreflight.validate_mount_path(Path("/var/run/docker.sock")) is False

    def test_disposable_sandbox_cleanup(self):
        """DisposableSandbox context manager must purge temporary directory on exit."""
        sandbox_id = "test_cleanup_sandbox_001"
        target_dir = SANDBOX_BASE_DIR / sandbox_id

        with DisposableSandbox(sandbox_id=sandbox_id) as sandbox:
            scratch_file = sandbox.sandbox_dir / "probe.txt"
            scratch_file.write_text("scratch data")
            assert scratch_file.exists()
            assert target_dir.exists()

        assert not target_dir.exists()

    def test_command_must_be_string_list(self):
        """execute_isolated_command must reject shell string interpolation."""
        with DisposableSandbox() as sandbox:
            res = sandbox.execute_isolated_command(command="echo 'injected'")  # not a list
            assert res.status == "failed"
            assert "Security violation" in res.stderr

    def test_docker_run_args_enforce_hardened_controls(self):
        """Docker run arguments must include --network=none, --read-only, dropped capabilities."""
        with DisposableSandbox() as sandbox:
            args = sandbox.build_docker_run_args("alpine:latest", ["id"])
            args_str = " ".join(args)
            assert "--network=none" in args_str
            assert "--read-only" in args_str
            assert "--cap-drop=ALL" in args_str
            assert "--security-opt=no-new-privileges:true" in args_str
            assert "--tmpfs=/tmp:rw,noexec,nosuid,size=32m" in args_str


class TestQemuUserModeEmulation:
    """FR-2.1: Architecture mapping, input validation, tool discovery."""

    @pytest.mark.parametrize(
        "arch,endian,expected_bin",
        [
            ("MIPS", "big", "qemu-mips"),
            ("MIPS", "little", "qemu-mipsel"),
            ("MIPSEL", "little", "qemu-mipsel"),
            ("ARM", "little", "qemu-arm"),
            ("ARM32", "little", "qemu-arm"),
            ("ARM", "big", "qemu-armeb"),
            ("ARM64", "little", "qemu-aarch64"),
            ("AArch64", "little", "qemu-aarch64"),
            ("x86_64", "little", "qemu-x86_64"),
            ("i386", "little", "qemu-i386"),
        ],
    )
    def test_qemu_architecture_mapping_matrix(self, arch, endian, expected_bin):
        assert QemuArchitectureMapper.get_qemu_binary(arch, endian) == expected_bin

    def test_input_path_validation(self, tmp_path: Path):
        """Emulation adapter must reject non-existent and 0-byte binaries without executing."""
        adapter = QemuEmulationAdapter()

        # Non-existent
        res_non = adapter.emulate_binary(tmp_path / "missing.bin", arch="ARM", endian="little")
        assert res_non.status == "failed"
        assert "does not exist" in res_non.stderr

        # 0-byte empty file
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        res_empty = adapter.emulate_binary(empty, arch="ARM", endian="little")
        assert res_empty.status == "failed"
        assert "empty (0 bytes)" in res_empty.stderr

    def test_qemu_tool_discovery_enumerates_targets(self):
        tools = QemuToolDiscovery.discover_tools()
        assert isinstance(tools, dict)
        for expected in ["qemu-mips", "qemu-arm", "qemu-aarch64", "qemu-x86_64"]:
            assert expected in tools


class TestSymbolicAndTaintAnalysis:
    """FR-3.1, FR-3.2, FR-3.4: Bounded symbolic analysis and taint reachability."""

    def test_angr_limitation_documented_honestly(self, tmp_path: Path):
        """When angr is not available on Python 3.14 Windows, limitations must explain why."""
        analyzer = BoundedSymbolicAnalyzer()
        report = analyzer.analyze_workspace(tmp_path)
        if not ANGR_AVAILABLE:
            assert report.angr_available is False
            assert any("angr symbolic execution engine is not available" in lim for lim in report.limitations)
            assert report.engine == "firmwarex_static_taint_v1"

    def test_taint_path_and_source_sink_modeling(self, tmp_path: Path):
        """Analyzer must recognize input sources (argv, getenv, recv) and dangerous sinks."""
        test_bin = tmp_path / "gateway_cli"
        elf_bytes = create_minimal_elf("arm", bitness=32, endianness="little")
        # Embed test symbol names
        test_bin.write_bytes(elf_bytes + b"\x00getenv\x00system\x00strcpy\x00")

        analyzer = BoundedSymbolicAnalyzer()
        leads = analyzer.analyze_binary(test_bin)

        assert len(leads) >= 1
        lead = leads[0]
        assert lead.status == "REVIEW_LEAD"
        assert lead.source_symbol in ("getenv", "argv", "recv")
        assert lead.sink_symbol in ("system", "strcpy", "memcpy", "sprintf")
        assert len(lead.tainted_path) >= 2
        assert lead.reaching_condition is not None
        assert "Attacker" in lead.reaching_condition

    def test_budget_exhaustion_reported_as_incomplete(self, tmp_path: Path):
        """When instruction/time budget is exhausted, analyzer must return budget_exhausted status."""
        test_bin = tmp_path / "test_app"
        test_bin.write_bytes(create_minimal_elf("x86_64"))

        strict_budget = SymbolicBudget(instruction_budget=10, timeout_seconds=0.01)
        analyzer = BoundedSymbolicAnalyzer(budget=strict_budget)
        report = analyzer.analyze_workspace(tmp_path)

        assert report.status == "budget_exhausted"
        assert any("budget constraints" in lim.lower() for lim in report.limitations)


class TestCrashStateReporting:
    """FR-3.3: Non-weaponized diagnostic crash-state reporting."""

    def test_parse_sigsegv_with_patterned_fault_address(self):
        """Capture fault address and registers; classify patterned 0x41414141 as CWE-120."""
        mock_stderr = (
            "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
            "fault address: 0x41414141\n"
            "pc = 0x0040058c\n"
            "sp = 0x7fffffffe010\n"
            "r0 = 0x00000000\n"
        )
        report = CrashStateParser.parse_crash(
            stdout="",
            stderr=mock_stderr,
            exit_code=-11,
            arch="ARM",
            binary_name="httpd",
        )

        assert report is not None
        assert report.signal == "SIGSEGV"
        assert report.fault_address == "0x41414141"
        assert report.registers is not None
        assert report.registers.get("pc") == "0x0040058c"
        assert report.registers.get("sp") == "0x7fffffffe010"
        assert report.candidate_cwe == "CWE-120"
        assert report.risk_rating == "critical"
        assert report.stack_hash is not None
        assert len(report.stack_hash) == 16

    def test_parse_null_pointer_dereference(self):
        """Classify 0x0 fault address as CWE-476 (NULL Pointer Dereference)."""
        mock_stderr = (
            "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n"
            "fault address: 0x00000000\n"
            "pc = 0x00401234\n"
        )
        report = CrashStateParser.parse_crash(
            stdout="",
            stderr=mock_stderr,
            exit_code=139,
            arch="MIPS",
            binary_name="cli",
        )

        assert report is not None
        assert report.signal == "SIGSEGV"
        assert report.fault_address == "0x00000000"
        assert report.candidate_cwe == "CWE-476"
        assert report.risk_rating == "medium"

    def test_clean_exit_returns_none(self):
        """Normal exit without crash indicators must return None."""
        report = CrashStateParser.parse_crash(
            stdout="Service initialized successfully",
            stderr="",
            exit_code=0,
            arch="x86_64",
            binary_name="app",
        )
        assert report is None


class TestSecretAndCryptoScanning:
    """SC-3.1, SC-3.2: Secret detection, salted fingerprinting, non-reversible redaction."""

    def test_salted_fingerprint_deterministic_and_safe(self):
        secret1 = "AKIAIOSFODNN7EXAMPLE"
        fp1 = Redactor.fingerprint(secret1)
        fp2 = Redactor.fingerprint(secret1)
        assert fp1 == fp2
        assert fp1.startswith("sha256:")
        assert secret1 not in fp1

        # Different secrets yield distinct fingerprints
        fp_diff = Redactor.fingerprint("AKIAIOSFODNN7DIFFERENT")
        assert fp1 != fp_diff

    def test_redaction_preserves_only_minimal_preview(self):
        aws = "AKIAIOSFODNN7EXAMPLE"
        redacted = Redactor.redact(aws)
        assert aws not in redacted
        assert redacted.startswith("AKI")
        assert redacted.endswith("PLE")
        assert "*" in redacted

    def test_empty_and_short_secret_handling(self):
        assert Redactor.redact("") == ""
        assert Redactor.fingerprint("") == ""
        assert Redactor.redact("abc") == "***"

    def test_secret_scanner_entropy_and_crypto(self, tmp_path: Path):
        cfg = tmp_path / "app.env"
        cfg.write_text("SECRET_KEY='4kL9mP2zQ8vR5tW1yB7cN3jK6xH8'\nMD5_FUNC='MD5_Init'\n")

        scanner = SecretScanner()
        findings = scanner.scan_file(cfg, "etc/app.env")
        assert len(findings) >= 2
        categories = [f.category for f in findings]
        assert "hardcoded_secret" in categories
        assert "weak_crypto" in categories


class TestFindingNormalizationSchema:
    """PRD Appendix A schema compliance across static, symbolic, and dynamic findings."""

    def test_from_symbolic_lead_schema_compliance(self):
        lead = SymbolicReviewLead(
            binary_path="bin/service",
            source_symbol="recv",
            sink_symbol="strcpy",
            cwe_id="CWE-120",
            category="memory_corruption",
            evidence="Data flows from recv to strcpy",
            confidence="candidate",
            tainted_path=["recv", "buffer_copy", "strcpy"],
            reaching_condition="Unconstrained network payload reaches strcpy",
        )
        finding = FindingNormaliser.from_symbolic_lead(lead, firmware_id="fw-123", architecture="ARM32")

        # Appendix A mandatory fields
        expected_keys = [
            "vulnerability_id", "firmware_id", "binary", "architecture", "category",
            "cwe", "address", "sink", "source", "tainted_path", "crash_state",
            "risk_rating", "confidence", "evidence_ref", "redacted", "remediation",
            "status", "detected_at", "details",
        ]
        for k in expected_keys:
            assert k in finding

        assert finding["binary"] == "bin/service"
        assert finding["architecture"] == "ARM32"
        assert finding["cwe"] == "CWE-120"
        assert finding["sink"] == "strcpy"
        assert finding["source"] == "recv"
        assert finding["tainted_path"] == ["recv", "buffer_copy", "strcpy"]

    def test_from_dynamic_crash_schema_compliance(self):
        crash = CrashReport(
            signal="SIGSEGV",
            fault_address="0x41414141",
            registers={"pc": "0x0040058c"},
            overflow_offset=4,
            stack_hash="a1b2c3d4e5f67890",
            candidate_cwe="CWE-120",
            risk_rating="critical",
            confidence="confirmed",
            diagnostic_summary="SIGSEGV observed",
            remediation="Add bounds check",
        )
        finding = FindingNormaliser.from_dynamic_crash(crash, firmware_id="fw-456", binary="bin/httpd", arch="MIPS")

        assert finding["category"] == "dynamic_crash"
        assert finding["cwe"] == "CWE-120"
        assert finding["risk_rating"] == "critical"
        assert finding["confidence"] == "confirmed"
        assert finding["crash_state"]["fault_address"] == "0x41414141"
        assert finding["crash_state"]["registers"] == {"pc": "0x0040058c"}
        assert finding["crash_state"]["stack_hash"] == "a1b2c3d4e5f67890"
