"""Modular QEMU User-Mode Emulation Adapter with strict containment controls.

Features:
1. Cross-architecture mapping (MIPS, MIPSEL, ARM, ARMEB, AArch64, x86_64).
2. QEMU toolchain discovery.
3. Containment preflight enforcement prior to execution.
4. Bounded execution limits (timeout, memory, output size cap).
5. Explicit diagnostic states (ready, unsupported_arch, missing_libraries, timeout, crashed, skipped).
6. Mock execution capability for verified deterministic testing without host execution risks.
"""

import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from firmwarex.isolation.sandbox_manager import (
    ContainmentPreflight,
    DisposableSandbox,
    IsolationConfig,
)

MAX_OUTPUT_CAPTURE_BYTES = 4096


@dataclass
class EmulationResult:
    """Structured telemetry output from a bounded user-mode emulation run."""
    status: str  # "completed", "unsupported_arch", "missing_libraries", "timeout", "crashed", "skipped", "failed"
    architecture: str
    qemu_binary: str | None
    exit_code: int | None
    stdout: str
    stderr: str
    termination_reason: str
    duration_ms: float
    is_mocked: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class QemuArchitectureMapper:
    """Maps ELF architecture and endianness to QEMU user-mode emulators."""

    ARCH_MAP = {
        ("mips", "big"): "qemu-mips",
        ("mips", "little"): "qemu-mipsel",
        ("arm", "little"): "qemu-arm",
        ("arm", "big"): "qemu-armeb",
        ("aarch64", "little"): "qemu-aarch64",
        ("arm64", "little"): "qemu-aarch64",
        ("x86_64", "little"): "qemu-x86_64",
        ("amd64", "little"): "qemu-x86_64",
        ("i386", "little"): "qemu-i386",
        ("x86", "little"): "qemu-i386",
    }

    @classmethod
    def get_qemu_binary(cls, arch: str, endian: str = "little") -> str | None:
        """Resolve the corresponding QEMU user binary name."""
        arch_norm = arch.lower().strip()
        endian_norm = endian.lower().strip()
        return cls.ARCH_MAP.get((arch_norm, endian_norm))


class QemuToolDiscovery:
    """Inspects host and container environments for QEMU user-mode binaries."""

    COMMON_BINARIES = [
        "qemu-mips",
        "qemu-mipsel",
        "qemu-arm",
        "qemu-aarch64",
        "qemu-x86_64",
        "qemu-i386",
    ]

    @classmethod
    def discover_tools(cls) -> dict[str, str | None]:
        """Check availability of QEMU user-mode binaries."""
        discovered = {}
        for binary in cls.COMMON_BINARIES:
            discovered[binary] = shutil.which(binary)
        return discovered


class QemuEmulationAdapter:
    """Safe adapter coordinating bounded emulation runs under strict isolation."""

    def __init__(self, timeout_seconds: int = 5, memory_limit: str = "128m"):
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit

    def emulate_binary(
        self,
        binary_path: Path,
        arch: str,
        endian: str = "little",
        args: list[str] | None = None,
    ) -> EmulationResult:
        """Attempt bounded user-mode emulation of an ELF binary.

        Fails closed if containment preflight is not satisfied.
        """
        start_time = time.time()
        qemu_bin = QemuArchitectureMapper.get_qemu_binary(arch, endian)
        if not qemu_bin:
            return EmulationResult(
                status="unsupported_arch",
                architecture=arch,
                qemu_binary=None,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=f"No QEMU user-mode emulator available for arch '{arch}' (endian: {endian}).",
                duration_ms=round((time.time() - start_time) * 1000, 2),
                is_mocked=False,
            )

        # 1. Enforce strict containment preflight check
        preflight = ContainmentPreflight.run_preflight()
        if not preflight.passed:
            return EmulationResult(
                status="skipped",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=(
                    "Emulation safely skipped: Containment preflight failed. "
                    "Host execution of untrusted firmware binaries is strictly forbidden."
                ),
                duration_ms=round((time.time() - start_time) * 1000, 2),
                is_mocked=False,
            )

        # 2. Check if QEMU binary is available in environment
        host_qemu = shutil.which(qemu_bin)
        if not host_qemu:
            return EmulationResult(
                status="skipped",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=f"QEMU binary '{qemu_bin}' is not installed in the execution environment.",
                duration_ms=round((time.time() - start_time) * 1000, 2),
                is_mocked=False,
            )

        # 3. If both container preflight passed and QEMU is present, execute inside DisposableSandbox
        try:
            iso_cfg = IsolationConfig(
                timeout_seconds=self.timeout_seconds,
                memory_limit=self.memory_limit,
                network_mode="none",
            )
            with DisposableSandbox(config=iso_cfg) as sandbox:
                # Stage binary in sandbox
                staged_binary = sandbox.sandbox_dir / binary_path.name
                shutil.copy2(binary_path, staged_binary)

                # Execute container run with timeout
                # When running in full container mode, command is assembled via sandbox
                # For safety on systems without the specific image built, report skipped
                return EmulationResult(
                    status="skipped",
                    architecture=arch,
                    qemu_binary=qemu_bin,
                    exit_code=None,
                    stdout="",
                    stderr="",
                    termination_reason="Preflight passed, but base firmwarex-qemu container image not landed.",
                    duration_ms=round((time.time() - start_time) * 1000, 2),
                    is_mocked=False,
                )

        except Exception as e:
            return EmulationResult(
                status="failed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=f"Emulation setup failed: {e!s}",
                duration_ms=round((time.time() - start_time) * 1000, 2),
                is_mocked=False,
            )

    def run_mock_emulation(
        self,
        arch: str,
        endian: str = "little",
        simulated_scenario: str = "success",
    ) -> EmulationResult:
        """Run simulated emulation scenarios for automated testing and harness validation.

        Simulates: success, timeout, missing_libraries, crashed, unsupported_arch.
        """
        qemu_bin = QemuArchitectureMapper.get_qemu_binary(arch, endian)
        if not qemu_bin:
            return EmulationResult(
                status="unsupported_arch",
                architecture=arch,
                qemu_binary=None,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=f"Unsupported architecture '{arch}'.",
                duration_ms=5.0,
                is_mocked=True,
            )

        if simulated_scenario == "timeout":
            return EmulationResult(
                status="timeout",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="[ERROR] Emulation timed out after 5.0 seconds.",
                termination_reason=f"Exceeded execution deadline ({self.timeout_seconds}s).",
                duration_ms=self.timeout_seconds * 1000.0,
                is_mocked=True,
            )
        elif simulated_scenario == "missing_libraries":
            return EmulationResult(
                status="missing_libraries",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=127,
                stdout="",
                stderr="/lib/ld-uClibc.so.0: No such file or directory",
                termination_reason="Missing dynamic linker or shared libraries in guest environment.",
                duration_ms=12.5,
                is_mocked=True,
            )
        elif simulated_scenario == "crashed":
            return EmulationResult(
                status="crashed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=-11,  # SIGSEGV
                stdout="",
                stderr="qemu: uncaught target signal 11 (Segmentation fault) - core dumped",
                termination_reason="Target process terminated with SIGSEGV (signal 11).",
                duration_ms=25.0,
                is_mocked=True,
            )
        else:
            return EmulationResult(
                status="completed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=0,
                stdout="Firmware daemon initialized (simulated).",
                stderr="",
                termination_reason="Process exited cleanly with status 0.",
                duration_ms=45.0,
                is_mocked=True,
            )
