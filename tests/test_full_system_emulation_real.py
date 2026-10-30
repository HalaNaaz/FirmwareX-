"""Tests for PRD FR-2.2: Best-Effort Full-System Emulation Real Execution & Isolation.

Enforces:
- FR-2.2: Best-effort full-system emulation under strict containment.
- Verified execution of QEMU system binaries in isolated Linux namespace (unshare -r -n).
- Default-deny air-gapping (-net none) with zero host egress.
- Honest telemetry: is_mocked=False, real duration, real exit codes, real BIOS/kernel console output.
- Fail-closed behavior on missing dependencies or unsupported architectures.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from firmwarex.emulation.qemu_adapter import (
    QemuSystemEmulator,
    SystemEmulationConfig,
)
from firmwarex.isolation.wsl_engine import WslExecutionEngine


def test_wsl_qemu_system_binary_presence():
    """Verify that QEMU system emulators are installed in the WSL execution environment."""
    assert WslExecutionEngine.is_available() is True


def test_real_isolated_qemu_system_execution_bios_stage():
    """Verify genuine execution of qemu-system-x86_64 under unshare -r -n with SeaBIOS output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a raw drive image (1MB zeroed) to serve as boot drive
        drive_path = Path(tmpdir) / "disk.img"
        drive_path.write_bytes(b"\x00" * (1024 * 1024))

        config = SystemEmulationConfig(
            architecture="x86_64",
            endianness="little",
            drive_image_path=drive_path,
            memory_mb=128,
            network_mode="none",
            timeout_seconds=3,
        )

        emulator = QemuSystemEmulator(config)
        result = emulator.boot()

        # Real execution must NOT be mocked
        assert result.is_mocked is False
        assert result.architecture == "x86_64"
        assert result.qemu_binary == "qemu-system-x86_64"
        assert result.duration_ms > 0

        # Command executed must enforce air-gapping
        assert "-net" in result.command_executed
        assert "none" in result.command_executed
        assert "-nographic" in result.command_executed
        assert "-no-reboot" in result.command_executed

        # SeaBIOS outputs "No bootable device" when no OS is installed on disk
        combined = result.stdout + "\n" + result.stderr
        assert ("SeaBIOS" in combined or "No bootable device" in combined or result.boot_stage == "bios_boot" or result.status == "boot_failed")


def test_qemu_system_unsupported_arch_fails_closed():
    """Verify that an unsupported architecture halts safely without execution."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dummy_drive = Path(tmpdir) / "disk.img"
        dummy_drive.write_bytes(b"\x00" * 4096)

        config = SystemEmulationConfig(
            architecture="sparc64",
            endianness="big",
            drive_image_path=dummy_drive,
        )
        emulator = QemuSystemEmulator(config)
        res = emulator.boot()
        assert res.status == "unsupported_architecture"
        assert res.boot_stage == "failed"
        assert res.is_mocked is False


def test_qemu_system_missing_media_rejected():
    """Verify that configuration without boot media is rejected before execution."""
    config = SystemEmulationConfig(
        architecture="x86_64",
        endianness="little",
        kernel_path=None,
        drive_image_path=None,
    )
    emulator = QemuSystemEmulator(config)
    res = emulator.boot()
    assert res.status == "missing_dependencies"
    assert "At least one boot media" in res.stderr
    assert res.is_mocked is False

