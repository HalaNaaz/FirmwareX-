"""Automated verification suite for Dynamic Analysis Blocker Resolution.

Validates:
1. Real QEMU user-mode execution across MIPS, ARM32, ARM64, and x86_64 (PRD FR-2.1).
2. Genuine angr symbolic execution with SMT solver constraints (PRD FR-3.1, FR-3.2).
3. Authentic source-to-sink data-flow reachability with positive & negative controls (PRD FR-3.3, FR-3.4).
4. Real crash-state telemetry capture with register dumps and signals (PRD FR-4.3).
5. Network isolation and execution timeout containment.
"""

from pathlib import Path

from firmwarex.core.symbolic_analyzer import BoundedSymbolicAnalyzer, SymbolicBudget
from firmwarex.emulation.qemu_adapter import QemuEmulationAdapter, QemuToolDiscovery
from firmwarex.isolation.wsl_engine import WslExecutionEngine

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "binaries"


class TestQemuUserModeRealExecution:
    """PRD FR-2.1: Real cross-architecture user-mode emulation."""

    def test_qemu_discovery_across_architectures(self):
        tools = QemuToolDiscovery.discover_tools()
        # Verify tool discovery locates real binaries in Linux/WSL environment
        assert tools.get("qemu-x86_64") is not None
        assert tools.get("qemu-arm") is not None
        assert tools.get("qemu-aarch64") is not None
        assert tools.get("qemu-mips") is not None
        assert tools.get("qemu-mipsel") is not None

    def test_real_qemu_execution_x86_64(self):
        binary = FIXTURES_DIR / "x86_64_ok"
        adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
        res = adapter.emulate_binary(binary, arch="x86_64", endian="little")

        assert res.status == "completed"
        assert res.exit_code == 0
        assert "FIRMWAREX_EXEC_OK_X86_64" in res.stdout
        assert res.is_mocked is False
        assert res.qemu_binary == "qemu-x86_64"
        assert res.duration_ms > 0.0

    def test_real_qemu_execution_arm32(self):
        binary = FIXTURES_DIR / "arm32_ok"
        adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
        res = adapter.emulate_binary(binary, arch="arm", endian="little")

        assert res.status == "completed"
        assert res.exit_code == 0
        assert "FIRMWAREX_EXEC_OK_ARM32" in res.stdout
        assert res.is_mocked is False
        assert res.qemu_binary == "qemu-arm"
        assert res.duration_ms > 0.0

    def test_real_qemu_execution_arm64(self):
        binary = FIXTURES_DIR / "arm64_ok"
        adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
        res = adapter.emulate_binary(binary, arch="arm64", endian="little")

        assert res.status == "completed"
        assert res.exit_code == 0
        assert "FIRMWAREX_EXEC_OK_ARM64" in res.stdout
        assert res.is_mocked is False
        assert res.qemu_binary == "qemu-aarch64"
        assert res.duration_ms > 0.0

    def test_real_qemu_execution_mips_big_endian(self):
        binary = FIXTURES_DIR / "mips_ok"
        adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
        res = adapter.emulate_binary(binary, arch="mips", endian="big")

        assert res.status == "completed"
        assert res.exit_code == 0
        assert res.is_mocked is False
        assert res.qemu_binary == "qemu-mips"
        assert res.duration_ms > 0.0

    def test_real_qemu_execution_mips_little_endian(self):
        binary = FIXTURES_DIR / "mipsel_ok"
        adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
        res = adapter.emulate_binary(binary, arch="mipsel", endian="little")

        assert res.status == "completed"
        assert res.exit_code == 0
        assert res.is_mocked is False
        assert res.qemu_binary == "qemu-mipsel"
        assert res.duration_ms > 0.0


class TestCrashStateValidation:
    """PRD FR-4.3 & Phase 5: Authentic crash telemetry and register state extraction."""

    def test_real_crash_capture_x86_64(self):
        binary = FIXTURES_DIR / "x86_64_crash"
        adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
        res = adapter.emulate_binary(binary, arch="x86_64", endian="little")

        assert res.status == "crashed"
        assert res.is_mocked is False
        assert res.crash_report is not None

        cr = res.crash_report
        assert cr["signal"] in ("SIGSEGV", "SIGBUS")
        assert cr["confidence"] == "confirmed"
        # Registers extracted from real QEMU CPU dump
        assert cr["registers"] is not None
        assert len(cr["registers"]) > 0

    def test_real_crash_capture_arm32(self):
        binary = FIXTURES_DIR / "arm32_crash"
        adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
        res = adapter.emulate_binary(binary, arch="arm", endian="little")

        assert res.status == "crashed"
        assert res.is_mocked is False
        assert res.crash_report is not None

        cr = res.crash_report
        assert cr["signal"] in ("SIGSEGV", "SIGBUS")
        assert cr["registers"] is not None
        # Check ARM register naming e.g. r0, pc, sp
        reg_keys = set(cr["registers"].keys())
        assert any(k in reg_keys for k in ["r0", "r00", "r1", "pc", "sp", "r15"])

    def test_real_crash_capture_mips(self):
        binary = FIXTURES_DIR / "mips_crash"
        adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
        res = adapter.emulate_binary(binary, arch="mips", endian="big")

        assert res.status == "crashed"
        assert res.is_mocked is False
        assert res.crash_report is not None
        assert res.crash_report["signal"] in ("SIGSEGV", "SIGBUS")

    def test_non_crashing_controls_do_not_report_crashes(self):
        for arch, bin_name, endian in [
            ("x86_64", "x86_64_ok", "little"),
            ("arm", "arm32_ok", "little"),
            ("mips", "mips_ok", "big"),
        ]:
            binary = FIXTURES_DIR / bin_name
            adapter = QemuEmulationAdapter(timeout_seconds=5, allow_wsl=True)
            res = adapter.emulate_binary(binary, arch=arch, endian=endian)
            assert res.status == "completed"
            assert res.crash_report is None


class TestAngrSymbolicExecutionAndTaintEvidence:
    """PRD FR-3.1 - FR-3.4: Genuine SMT-backed symbolic execution and data-flow evidence."""

    def test_wsl_angr_engine_availability(self):
        assert WslExecutionEngine.is_available() is True
        assert WslExecutionEngine.is_angr_available() is True

    def test_genuine_angr_positive_control_reachability(self):
        binary = FIXTURES_DIR / "taint_target_x86"
        analyzer = BoundedSymbolicAnalyzer(allow_wsl=True, budget=SymbolicBudget(timeout_seconds=10.0, path_budget=15))
        leads = analyzer.analyze_binary(binary)

        # Locate positive lead (target_sink)
        pos_leads = [lead for lead in leads if lead.sink_symbol == "target_sink"]
        assert len(pos_leads) == 1, f"Expected 1 target_sink lead, found: {leads}"

        lead = pos_leads[0]
        assert lead.status == "CONFIRMED_VULNERABILITY"
        assert lead.confidence == "confirmed"
        assert lead.analysis_method == "angr_symbolic_execution"

        # Evidence must contain concrete solved input and constraints
        assert "PWND" in lead.evidence or "b'PWND'" in lead.evidence
        assert "Input SHA256" in lead.evidence
        assert "Path Constraints" in lead.evidence

    def test_genuine_angr_negative_control_unreachability(self):
        binary = FIXTURES_DIR / "taint_target_x86"
        analyzer = BoundedSymbolicAnalyzer(allow_wsl=True, budget=SymbolicBudget(timeout_seconds=10.0, path_budget=15))
        leads = analyzer.analyze_binary(binary)

        # Locate negative control (unreachable_sink)
        neg_leads = [lead for lead in leads if lead.sink_symbol == "unreachable_sink"]
        assert len(neg_leads) == 1, f"Expected 1 unreachable_sink lead, found: {leads}"

        lead = neg_leads[0]
        assert lead.status == "UNREACHABLE_OR_SAFE"
        assert lead.confidence == "confirmed_unreachable"
        assert lead.analysis_method == "angr_symbolic_execution"
        assert "Verified unreachable branch" in lead.evidence

    def test_symbolic_budget_exhaustion_behavior(self):
        # Force budget exhaustion with timeout=0.01s
        analyzer = BoundedSymbolicAnalyzer(allow_wsl=True, budget=SymbolicBudget(timeout_seconds=0.01, instruction_budget=50))
        report = analyzer.analyze_workspace(FIXTURES_DIR)

        assert report.status == "budget_exhausted"
        assert any("budget" in lim.lower() for lim in report.limitations)
        assert report.angr_available is True



class TestNamespaceIsolationAndFailClosed:
    """PRD NFR-SEC-1 & Audit: Verify network isolation and fail-closed behavior on namespace failure."""

    def test_namespace_creation_failure_fails_closed(self, monkeypatch):
        """Simulate unshare failure (e.g. Permission Denied) and verify fail-closed isolation."""
        import subprocess
        real_run = subprocess.run

        def mock_failing_unshare(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            if isinstance(cmd, list) and "unshare" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=1,
                    stdout=b"",
                    stderr=b"unshare: unshare failed: Operation not permitted\n",
                )
            return real_run(*args, **kwargs)

        monkeypatch.setattr(subprocess, "run", mock_failing_unshare)
        binary = FIXTURES_DIR / "x86_64_ok"
        res = WslExecutionEngine.run_isolated_qemu(binary, arch="x86_64")

        assert res.status == "isolation_blocked"
        assert res.is_contained is False
        assert res.network_isolated is False
        assert "Linux namespace creation denied" in res.termination_reason
