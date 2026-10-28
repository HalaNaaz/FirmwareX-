"""Unit tests for QEMU architecture mapping, tool discovery, and bounded emulation."""

from firmwarex.emulation.qemu_adapter import (
    QemuArchitectureMapper,
    QemuEmulationAdapter,
    QemuToolDiscovery,
)


def test_qemu_architecture_mapping():
    """Verify correct mapping of ELF architecture + endianness to QEMU user binaries."""
    assert QemuArchitectureMapper.get_qemu_binary("MIPS", "big") == "qemu-mips"
    assert QemuArchitectureMapper.get_qemu_binary("MIPS", "little") == "qemu-mipsel"
    assert QemuArchitectureMapper.get_qemu_binary("ARM", "little") == "qemu-arm"
    assert QemuArchitectureMapper.get_qemu_binary("ARM", "big") == "qemu-armeb"
    assert QemuArchitectureMapper.get_qemu_binary("AArch64", "little") == "qemu-aarch64"
    assert QemuArchitectureMapper.get_qemu_binary("x86_64", "little") == "qemu-x86_64"
    assert QemuArchitectureMapper.get_qemu_binary("SPARC", "big") is None


def test_qemu_tool_discovery():
    """Verify QEMU tool discovery returns dictionary of expected emulator binaries."""
    tools = QemuToolDiscovery.discover_tools()
    assert isinstance(tools, dict)
    assert "qemu-mips" in tools
    assert "qemu-arm" in tools
    assert "qemu-x86_64" in tools


def test_qemu_emulate_unsupported_arch(tmp_path):
    """Verify that unsupported architectures return explicit unsupported_arch status."""
    adapter = QemuEmulationAdapter()
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x7fELF")

    res = adapter.emulate_binary(dummy, arch="UNKNOWN_CHIP", endian="little")
    assert res.status in ("unsupported_architecture", "unsupported_arch")
    assert "No QEMU user-mode emulator available" in res.termination_reason


def test_qemu_emulate_skips_when_host_binary_missing(tmp_path):
    """Verify that emulation skips gracefully when QEMU binary is absent without executing on host."""
    adapter = QemuEmulationAdapter()
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"\x7fELF")

    # MIPS emulation on Windows host without qemu-mips.exe
    res = adapter.emulate_binary(dummy, arch="MIPS", endian="big")
    assert res.status in ("tool_unavailable", "skipped")
    assert "Host execution of untrusted firmware binaries is strictly forbidden" in res.termination_reason or "not installed" in res.termination_reason


def test_qemu_mock_scenarios():
    """Verify mock execution harness models timeout, missing libraries, crashed, and success."""
    adapter = QemuEmulationAdapter(timeout_seconds=5)

    # 1. Timeout scenario
    res_to = adapter.run_mock_emulation(arch="ARM", endian="little", simulated_scenario="timeout")
    assert res_to.status == "timeout"
    assert res_to.is_mocked is True
    assert "timed out" in res_to.stderr.lower()

    # 2. Missing libraries scenario
    res_lib = adapter.run_mock_emulation(arch="MIPS", endian="big", simulated_scenario="missing_libraries")
    assert res_lib.status == "missing_libraries"
    assert res_lib.exit_code == 127
    assert "ld-uClibc.so" in res_lib.stderr

    # 3. Crash scenario (SIGSEGV)
    res_crash = adapter.run_mock_emulation(arch="x86_64", endian="little", simulated_scenario="crashed")
    assert res_crash.status == "crashed"
    assert res_crash.exit_code == -11
    assert "Segmentation fault" in res_crash.stderr

    # 4. Clean exit scenario
    res_clean = adapter.run_mock_emulation(arch="ARM", endian="little", simulated_scenario="success")
    assert res_clean.status == "completed"
    assert res_clean.exit_code == 0
    assert "simulated" in res_clean.stdout
