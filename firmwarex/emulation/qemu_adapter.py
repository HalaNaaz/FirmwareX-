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
from dataclasses import asdict, dataclass, field
from pathlib import Path

from firmwarex.emulation.crash_parser import CrashStateParser
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
    crash_report: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class QemuArchitectureMapper:
    """Maps ELF architecture and endianness to QEMU user-mode emulators."""

    ARCH_MAP = {
        ("mips", "big"): "qemu-mips",
        ("mips", "little"): "qemu-mipsel",
        ("mipsel", "little"): "qemu-mipsel",
        ("mipsel", "big"): "qemu-mipsel",
        ("arm", "little"): "qemu-arm",
        ("arm32", "little"): "qemu-arm",
        ("arm32", "big"): "qemu-armeb",
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
        if bin_path:
            try:
                res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, timeout=3)
                if res.returncode == 0 and res.stdout:
                    return res.stdout.strip().splitlines()[0]
            except Exception:
                pass
        from firmwarex.isolation.wsl_engine import WslExecutionEngine
        return WslExecutionEngine.get_qemu_version(binary_name)

    @classmethod
    def discover_tools(cls) -> dict[str, str | None]:
        """Check availability of QEMU user-mode binaries across host and isolated Linux runtimes."""
        discovered = {}
        for binary in cls.COMMON_BINARIES:
            discovered[binary] = shutil.which(binary)
        from firmwarex.isolation.wsl_engine import WslExecutionEngine
        if WslExecutionEngine.is_available():
            wsl_tools = WslExecutionEngine.discover_qemu_tools()
            for binary, path in wsl_tools.items():
                if not discovered.get(binary) and path:
                    discovered[binary] = f"[WSL2] {path}"
        return discovered


class QemuEmulationAdapter:
    """Safe adapter coordinating bounded emulation runs under strict isolation."""

    def __init__(
        self,
        timeout_seconds: int = 5,
        memory_limit: str = "128m",
        allow_wsl: bool = False,
    ):
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.allow_wsl = allow_wsl

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
        if not binary_path.exists() or not binary_path.is_file():
            return EmulationResult(
                status="failed",
                architecture=arch,
                qemu_binary=None,
                exit_code=None,
                stdout="",
                stderr=f"Target binary '{binary_path}' does not exist or is not a regular file.",
                termination_reason="File not found or invalid file path.",
                duration_ms=0.0,
                is_mocked=False,
            )

        if binary_path.stat().st_size == 0:
            return EmulationResult(
                status="failed",
                architecture=arch,
                qemu_binary=None,
                exit_code=None,
                stdout="",
                stderr="Target binary is empty (0 bytes).",
                termination_reason="Cannot emulate 0-byte binary.",
                duration_ms=0.0,
                is_mocked=False,
            )

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
            if self.allow_wsl:
                from firmwarex.isolation.wsl_engine import WslExecutionEngine
                if WslExecutionEngine.is_available() and WslExecutionEngine.discover_qemu_tools().get(qemu_bin):
                    wsl_res = WslExecutionEngine.run_isolated_qemu(
                        binary_path=binary_path,
                        arch=arch,
                        endian=endian,
                        args=args,
                        timeout_seconds=float(self.timeout_seconds),
                    )
                    return EmulationResult(
                        status=wsl_res.status,
                        architecture=wsl_res.architecture,
                        qemu_binary=wsl_res.qemu_binary,
                        exit_code=wsl_res.exit_code,
                        stdout=wsl_res.stdout,
                        stderr=wsl_res.stderr,
                        termination_reason=wsl_res.termination_reason,
                        duration_ms=wsl_res.duration_ms,
                        is_mocked=False,
                        crash_report=wsl_res.crash_report,
                    )

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
            mock_stderr = "qemu: uncaught target signal 11 (Segmentation fault) - core dumped\nfault address: 0x41414141\npc: 0x0040058c\nsp: 0x7fffffffe010"
            crash_rep = CrashStateParser.parse_crash(
                stdout="",
                stderr=mock_stderr,
                exit_code=-11,
                arch=arch,
                binary_name="simulated_binary",
            )
            return EmulationResult(
                status="crashed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=-11,
                stdout="",
                stderr=mock_stderr,
                termination_reason="Guest program terminated by SIGSEGV.",
                duration_ms=12.2,
                is_mocked=True,
                crash_report=crash_rep.to_dict() if crash_rep else None,
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


# ==================== FULL-SYSTEM EMULATION (PRD FR-2.2) ====================

@dataclass
class SystemBootResult:
    """Telemetry report representing a best-effort full-system emulation boot attempt."""
    status: str  # "boot_successful", "boot_failed", "unsupported_architecture", "unsupported_machine", "missing_dependencies", "isolation_blocked", "timeout", "tool_unavailable"
    architecture: str
    machine_type: str
    qemu_binary: str | None
    boot_stage: str  # "firmware_loaded", "kernel_boot", "init_started", "shell_ready", "failed", "none"
    exit_code: int | None
    duration_ms: float
    stdout: str
    stderr: str
    diagnostic_summary: str
    command_executed: list[str] = field(default_factory=list)
    is_mocked: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class QemuSystemArchitectureMapper:
    """Maps system architectures to QEMU system emulators and hardware board profiles."""

    SYSTEM_PROFILES = {
        ("mips", "big"): {
            "binary": "qemu-system-mips",
            "machine": "malta",
            "cpu": "24Kf",
            "default_memory": 256,
            "serial": "ttyS0",
        },
        ("mips", "little"): {
            "binary": "qemu-system-mipsel",
            "machine": "malta",
            "cpu": "24Kf",
            "default_memory": 256,
            "serial": "ttyS0",
        },
        ("mipsel", "little"): {
            "binary": "qemu-system-mipsel",
            "machine": "malta",
            "cpu": "24Kf",
            "default_memory": 256,
            "serial": "ttyS0",
        },
        ("arm", "little"): {
            "binary": "qemu-system-arm",
            "machine": "virt",
            "cpu": "cortex-a15",
            "default_memory": 512,
            "serial": "ttyAMA0",
        },
        ("arm32", "little"): {
            "binary": "qemu-system-arm",
            "machine": "virt",
            "cpu": "cortex-a15",
            "default_memory": 512,
            "serial": "ttyAMA0",
        },
        ("aarch64", "little"): {
            "binary": "qemu-system-aarch64",
            "machine": "virt",
            "cpu": "cortex-a57",
            "default_memory": 512,
            "serial": "ttyAMA0",
        },
        ("arm64", "little"): {
            "binary": "qemu-system-aarch64",
            "machine": "virt",
            "cpu": "cortex-a57",
            "default_memory": 512,
            "serial": "ttyAMA0",
        },
        ("x86_64", "little"): {
            "binary": "qemu-system-x86_64",
            "machine": "q35",
            "cpu": "max",
            "default_memory": 512,
            "serial": "ttyS0",
        },
        ("i386", "little"): {
            "binary": "qemu-system-i386",
            "machine": "pc",
            "cpu": "qemu32",
            "default_memory": 256,
            "serial": "ttyS0",
        },
    }

    @classmethod
    def get_system_profile(cls, arch: str, endian: str = "little") -> dict | None:
        """Resolve board machine and QEMU system binary for architecture."""
        arch_norm = arch.lower().strip()
        endian_norm = endian.lower().strip()
        return cls.SYSTEM_PROFILES.get((arch_norm, endian_norm))


@dataclass
class SystemEmulationConfig:
    """Configuration bounding a full-system emulation attempt."""
    architecture: str
    endianness: str = "little"
    machine_type: str | None = None
    cpu_model: str | None = None
    memory_mb: int = 256
    timeout_seconds: int = 30
    kernel_path: Path | None = None
    initrd_path: Path | None = None
    drive_image_path: Path | None = None
    dtb_path: Path | None = None
    kernel_cmdline: str = "console=ttyS0 root=/dev/ram0 rw init=/init quiet"
    network_mode: str = "none"  # Strict default-deny: "none"
    use_disposable_overlay: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kernel_path"] = str(self.kernel_path) if self.kernel_path else None
        d["initrd_path"] = str(self.initrd_path) if self.initrd_path else None
        d["drive_image_path"] = str(self.drive_image_path) if self.drive_image_path else None
        d["dtb_path"] = str(self.dtb_path) if self.dtb_path else None
        return d


class QemuSystemEmulator:
    """Executes or models best-effort full-system firmware boots under strict isolation."""

    def __init__(self, config: SystemEmulationConfig):
        self.config = config

    def validate_config(self) -> tuple[bool, str]:
        """Validate system emulation configuration before attempting boot."""
        profile = QemuSystemArchitectureMapper.get_system_profile(
            self.config.architecture, self.config.endianness
        )
        if not profile:
            return False, f"Unsupported architecture '{self.config.architecture}' (endian: {self.config.endianness})"

        if not self.config.kernel_path and not self.config.drive_image_path:
            return False, "At least one boot media (kernel_path or drive_image_path) must be supplied."

        if self.config.kernel_path:
            if not self.config.kernel_path.exists():
                return False, f"Kernel file not found: {self.config.kernel_path}"
            if self.config.kernel_path.stat().st_size < 512:
                return False, f"Kernel file invalid or too small ({self.config.kernel_path.stat().st_size} bytes)."

        if self.config.drive_image_path:
            if not self.config.drive_image_path.exists():
                return False, f"Drive image file not found: {self.config.drive_image_path}"

        if self.config.network_mode != "none":
            return False, f"Strict isolation violated: network_mode must be 'none', got '{self.config.network_mode}'"

        return True, "Configuration valid."

    def build_command(self, overlay_path: Path | None = None) -> list[str]:
        """Construct isolated QEMU system command line with default-deny air-gapping."""
        profile = QemuSystemArchitectureMapper.get_system_profile(
            self.config.architecture, self.config.endianness
        )
        qemu_bin = profile["binary"] if profile else "qemu-system"
        machine = self.config.machine_type or (profile["machine"] if profile else "virt")
        cpu = self.config.cpu_model or (profile["cpu"] if profile else "max")

        cmd = [
            qemu_bin,
            "-M", machine,
            "-cpu", cpu,
            "-m", f"{self.config.memory_mb}M",
            "-nographic",
            "-no-reboot",
            "-net", "none",  # Default-deny external networking
        ]

        if self.config.kernel_path:
            cmd.extend(["-kernel", str(self.config.kernel_path)])

        if self.config.initrd_path:
            cmd.extend(["-initrd", str(self.config.initrd_path)])

        drive_target = overlay_path or self.config.drive_image_path
        if drive_target:
            cmd.extend(["-drive", f"file={drive_target},format=raw,if=ide"])

        if self.config.dtb_path:
            cmd.extend(["-dtb", str(self.config.dtb_path)])

        if self.config.kernel_cmdline:
            cmd.extend(["-append", self.config.kernel_cmdline])

        return cmd

    def boot(self, simulated_scenario: str | None = None) -> SystemBootResult:
        """Execute or model full-system emulation run with strict containment gates."""
        start_time = time.time()
        profile = QemuSystemArchitectureMapper.get_system_profile(
            self.config.architecture, self.config.endianness
        )

        if not profile:
            return SystemBootResult(
                status="unsupported_architecture",
                architecture=self.config.architecture,
                machine_type=self.config.machine_type or "unknown",
                qemu_binary=None,
                boot_stage="failed",
                exit_code=None,
                duration_ms=round((time.time() - start_time) * 1000, 2),
                stdout="",
                stderr=f"Unsupported architecture '{self.config.architecture}'",
                diagnostic_summary="Architecture profile could not be resolved.",
                is_mocked=False,
            )

        qemu_bin = profile["binary"]
        machine = self.config.machine_type or profile["machine"]

        # Deterministic simulation / mock execution mode
        if simulated_scenario is not None:
            if simulated_scenario == "boot_successful":
                return SystemBootResult(
                    status="boot_successful",
                    architecture=self.config.architecture,
                    machine_type=machine,
                    qemu_binary=qemu_bin,
                    boot_stage="shell_ready",
                    exit_code=0,
                    duration_ms=450.0,
                    stdout=(
                        "Linux version 5.10.0 (firmwarex@builder) #1 PREEMPT\n"
                        "Machine model: " + machine + "\n"
                        "VFS: Mounted root (ramfs filesystem) on device 1:0.\n"
                        "Freeing unused kernel memory: 1024K\n"
                        "Run /init as init process\n"
                        "/bin/sh: can't access tty; job control turned off\n"
                        "/ # \n"
                    ),
                    stderr="",
                    diagnostic_summary="Guest operating system booted successfully to user-space shell.",
                    command_executed=self.build_command(),
                    is_mocked=True,
                )
            elif simulated_scenario == "boot_failed":
                return SystemBootResult(
                    status="boot_failed",
                    architecture=self.config.architecture,
                    machine_type=machine,
                    qemu_binary=qemu_bin,
                    boot_stage="kernel_boot",
                    exit_code=1,
                    duration_ms=180.0,
                    stdout="Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)\n",
                    stderr="qemu-system: fatal: Kernel panic encountered during guest initialization.\n",
                    diagnostic_summary="Guest kernel panic: unable to mount root filesystem overlay.",
                    command_executed=self.build_command(),
                    is_mocked=True,
                )
            elif simulated_scenario == "timeout":
                return SystemBootResult(
                    status="timeout",
                    architecture=self.config.architecture,
                    machine_type=machine,
                    qemu_binary=qemu_bin,
                    boot_stage="kernel_boot",
                    exit_code=None,
                    duration_ms=float(self.config.timeout_seconds * 1000),
                    stdout="Starting kernel ...\n",
                    stderr=f"Emulation exceeded wall-clock budget of {self.config.timeout_seconds}s.",
                    diagnostic_summary=f"Boot timed out after {self.config.timeout_seconds}s.",
                    command_executed=self.build_command(),
                    is_mocked=True,
                )

        is_valid, reason = self.validate_config()
        if not is_valid:
            return SystemBootResult(
                status="missing_dependencies",
                architecture=self.config.architecture,
                machine_type=machine,
                qemu_binary=qemu_bin,
                boot_stage="failed",
                exit_code=None,
                duration_ms=round((time.time() - start_time) * 1000, 2),
                stdout="",
                stderr=reason,
                diagnostic_summary=reason,
                is_mocked=False,
            )

        # 1. Enforce containment isolation preflight
        from firmwarex.isolation.wsl_engine import WslExecutionEngine
        wsl_ready = WslExecutionEngine.is_available()
        if not wsl_ready:
            preflight = ContainmentPreflight.run_preflight()
            if not preflight.passed:
                return SystemBootResult(
                    status="isolation_blocked",
                    architecture=self.config.architecture,
                    machine_type=machine,
                    qemu_binary=qemu_bin,
                    boot_stage="failed",
                    exit_code=None,
                    duration_ms=round((time.time() - start_time) * 1000, 2),
                    stdout="",
                    stderr="System emulation blocked: Container/WSL runtime unavailable. Bare-host system emulation is denied.",
                    diagnostic_summary="Containment preflight failed closed: Dynamic execution prohibited on bare host.",
                    command_executed=self.build_command(),
                    is_mocked=False,
                )

        # 2. Translate arguments and paths for WSL containment execution
        cpu = self.config.cpu_model or (profile["cpu"] if profile else "max")
        system_args: list[str] = [
            "-M", machine,
            "-cpu", cpu,
            "-m", f"{self.config.memory_mb}M",
            "-nographic",
            "-no-reboot",
            "-net", "none",
        ]

        if self.config.kernel_path:
            system_args.extend(["-kernel", WslExecutionEngine.to_wsl_path(self.config.kernel_path)])

        if self.config.initrd_path:
            system_args.extend(["-initrd", WslExecutionEngine.to_wsl_path(self.config.initrd_path)])

        drive_target = self.config.drive_image_path
        if drive_target:
            system_args.extend(["-drive", f"file={WslExecutionEngine.to_wsl_path(drive_target)},format=raw,if=ide"])

        if self.config.dtb_path:
            system_args.extend(["-dtb", WslExecutionEngine.to_wsl_path(self.config.dtb_path)])

        if self.config.kernel_cmdline:
            system_args.extend(["-append", self.config.kernel_cmdline])

        # 3. Execute inside verified isolated namespace under unshare -r -n
        res = WslExecutionEngine.run_isolated_qemu_system(
            qemu_bin=qemu_bin,
            system_args=system_args,
            timeout_seconds=float(self.config.timeout_seconds),
        )

        combined = (res.stdout + "\n" + res.stderr)
        if res.status == "timeout":
            boot_stage = "kernel_boot"
            boot_status = "timeout"
            diag = f"Boot timed out after {self.config.timeout_seconds}s."
        elif any(kw in combined for kw in ("/bin/sh", "login:", "root@", "shell_ready")):
            boot_stage = "shell_ready"
            boot_status = "boot_successful"
            diag = "Guest system booted successfully to user-space shell."
        elif "Kernel panic" in combined or "panic" in combined.lower():
            boot_stage = "kernel_boot"
            boot_status = "boot_failed"
            diag = "Guest kernel panic encountered during boot sequence."
        elif "No bootable device" in combined or "could not read the boot disk" in combined:
            boot_stage = "bios_boot"
            boot_status = "boot_failed"
            diag = "Firmware BIOS halted: no bootable OS payload found on drive."
        elif res.exit_code == 0:
            boot_stage = "boot_completed"
            boot_status = "boot_successful"
            diag = "QEMU system emulator executed and cleanly shut down."
        elif res.status == "isolation_blocked":
            boot_stage = "failed"
            boot_status = "isolation_blocked"
            diag = res.termination_reason
        elif res.status == "tool_unavailable":
            boot_stage = "none"
            boot_status = "tool_unavailable"
            diag = res.termination_reason
        else:
            boot_stage = "failed"
            boot_status = "boot_failed"
            diag = res.termination_reason or "System emulation failed."

        return SystemBootResult(
            status=boot_status,
            architecture=self.config.architecture,
            machine_type=machine,
            qemu_binary=qemu_bin,
            boot_stage=boot_stage,
            exit_code=res.exit_code,
            duration_ms=res.duration_ms,
            stdout=res.stdout,
            stderr=res.stderr,
            diagnostic_summary=diag,
            command_executed=[qemu_bin, *system_args],
            is_mocked=False,
        )
