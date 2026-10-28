"""Modular QEMU User-Mode Emulation Adapter with strict containment controls.

Features:
1. Cross-architecture mapping (MIPS, MIPSEL, ARM, ARMEB, AArch64, x86_64).
2. QEMU toolchain discovery.
3. Containment preflight enforcement prior to execution.
4. Bounded execution limits (timeout, memory, output size cap).
5. Explicit diagnostic states: tool_unavailable, isolation_blocked, unsupported_architecture, timeout, crashed, completed.
6. Mock execution capability for verified deterministic testing without host execution risks.
"""

import shutil
import subprocess
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
    status: str  # "completed", "unsupported_architecture", "missing_libraries", "timeout", "crashed", "tool_unavailable", "isolation_blocked", "failed"
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
    def get_tool_version(cls, binary_name: str) -> str | None:
        """Get version string of an available QEMU user-mode binary."""
        bin_path = shutil.which(binary_name)
        if not bin_path:
            return None
        try:
            res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, timeout=3)
            return res.stdout.strip().splitlines()[0] if res.returncode == 0 else None
        except Exception:
            return None

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
        container_image: str = "redis:7-alpine",
    ) -> EmulationResult:
        """Attempt bounded user-mode emulation of an ELF binary inside verified container isolation.

        Returns distinct states:
        - unsupported_architecture: Architecture not mapped to QEMU user binary.
        - isolation_blocked: Containment preflight failed closed.
        - tool_unavailable: QEMU binary not present in environment.
        - timeout: Bounded runtime budget exceeded.
        - crashed: Non-zero exit code, signal termination, or library fault.
        - completed: Execution succeeded under verified isolation.

        Never falls back to Windows host execution.
        """
        start_time = time.time()
        qemu_bin = QemuArchitectureMapper.get_qemu_binary(arch, endian)
        if not qemu_bin:
            return EmulationResult(
                status="unsupported_architecture",
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
                status="isolation_blocked",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=(
                    "Emulation blocked: Containment preflight failed closed. "
                    "Host execution of untrusted firmware binaries is strictly forbidden."
                ),
                duration_ms=round((time.time() - start_time) * 1000, 2),
                is_mocked=False,
            )

        # 2. Check if QEMU binary is available in environment
        host_qemu = shutil.which(qemu_bin)
        if not host_qemu:
            return EmulationResult(
                status="tool_unavailable",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=(
                    f"QEMU user-mode binary '{qemu_bin}' is not installed in the system environment. "
                    "Emulation safely deferred to maintain host containment."
                ),
                duration_ms=round((time.time() - start_time) * 1000, 2),
                is_mocked=False,
            )

        # 3. Execute inside DisposableSandbox under verified container isolation
        try:
            iso_cfg = IsolationConfig(
                timeout_seconds=self.timeout_seconds,
                memory_limit=self.memory_limit,
                network_mode="none",
            )
            with DisposableSandbox(config=iso_cfg) as sandbox:
                # Stage binary inside sandbox directory
                staged_binary = sandbox.sandbox_dir / binary_path.name
                shutil.copy2(binary_path, staged_binary)

                cmd = [qemu_bin, f"/workspace/{binary_path.name}"]
                if args:
                    cmd.extend(args)

                exec_res = sandbox.execute_isolated_command(
                    command=cmd,
                    image=container_image,
                    timeout_seconds=self.timeout_seconds,
                    max_output_bytes=MAX_OUTPUT_CAPTURE_BYTES,
                )

                duration = round((time.time() - start_time) * 1000, 2)

                if exec_res.status == "timeout":
                    return EmulationResult(
                        status="timeout",
                        architecture=arch,
                        qemu_binary=qemu_bin,
                        exit_code=None,
                        stdout=exec_res.stdout,
                        stderr=exec_res.stderr,
                        termination_reason=f"Emulation timed out after {self.timeout_seconds} seconds.",
                        duration_ms=duration,
                        is_mocked=False,
                    )

                if exec_res.exit_code != 0:
                    diag = f"Process exited with code {exec_res.exit_code}."
                    if "cannot open shared object file" in exec_res.stderr or "No such file" in exec_res.stderr:
                        diag += " Missing target dynamic libraries."
                    return EmulationResult(
                        status="crashed",
                        architecture=arch,
                        qemu_binary=qemu_bin,
                        exit_code=exec_res.exit_code,
                        stdout=exec_res.stdout,
                        stderr=exec_res.stderr,
                        termination_reason=diag,
                        duration_ms=duration,
                        is_mocked=False,
                    )

                return EmulationResult(
                    status="completed",
                    architecture=arch,
                    qemu_binary=qemu_bin,
                    exit_code=0,
                    stdout=exec_res.stdout,
                    stderr=exec_res.stderr,
                    termination_reason="Execution completed successfully inside isolated container.",
                    duration_ms=duration,
                    is_mocked=False,
                )

        except Exception as e:
            return EmulationResult(
                status="crashed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=f"Emulation execution failed: {e!s}",
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
                status="unsupported_architecture",
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
                stderr="Bounded execution timed out after 5000ms wall-clock limit.",
                termination_reason="Bounded execution exceeded 5000ms wall-clock limit.",
                duration_ms=5000.0,
                is_mocked=True,
            )
        elif simulated_scenario == "missing_libraries":
            return EmulationResult(
                status="missing_libraries",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=127,
                stdout="",
                stderr=f"/lib/ld-uClibc.so.0: No such file or directory (emulating {arch})",
                termination_reason="Missing guest dynamic linker or rootfs shared libraries.",
                duration_ms=18.5,
                is_mocked=True,
            )
        elif simulated_scenario == "crashed":
            return EmulationResult(
                status="crashed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=-11,
                stdout="",
                stderr="qemu: uncaught target signal 11 (Segmentation fault) - core dumped",
                termination_reason="Guest program terminated by SIGSEGV.",
                duration_ms=12.2,
                is_mocked=True,
            )
        else:
            return EmulationResult(
                status="completed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=0,
                stdout="simulated: FirmwareX Mock Service Initialized\nListening on 0.0.0.0:80\n",
                stderr="",
                termination_reason="Exit code 0",
                duration_ms=45.2,
                is_mocked=True,
            )
