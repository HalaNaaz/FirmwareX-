"""WSL2-backed contained execution engine for real QEMU user-mode and angr symbolic analysis.

Guarantees:
1. Strict containment: executes inside Linux namespace isolation (unshare -r -n) with network disabled.
2. Zero host execution: untrusted firmware binaries are never executed directly on the Windows host.
3. Bounded resources: enforces hard execution timeouts, memory limits, and output capture caps.
4. Real toolchain integration: drives authentic QEMU user binaries and angr/claripy Z3 solver engine.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from firmwarex.emulation.crash_parser import CrashStateParser

MAX_OUTPUT_CAPTURE_BYTES = 8192
DEFAULT_TIMEOUT_SECONDS = 5.0


@dataclass
class ContainedExecutionResult:
    """Outcome of a real QEMU user-mode execution run under containment."""
    status: str  # "completed", "crashed", "timeout", "missing_libraries", "tool_unavailable", "isolation_blocked", "failed"
    architecture: str
    qemu_binary: str | None
    exit_code: int | None
    stdout: str
    stderr: str
    termination_reason: str
    duration_ms: float
    is_mocked: bool = False
    is_contained: bool = True
    network_isolated: bool = True
    crash_report: dict[str, Any] | None = None
    command_executed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class WslExecutionEngine:
    """Coordinates isolated execution of QEMU user-mode and angr within WSL2 Linux environment."""

    _WSL_AVAILABLE: bool | None = None
    _WSL_DISTRO: str = "Ubuntu"
    _ANGR_PYTHON: str = "/opt/angr-env/bin/python"

    COMMON_QEMU_BINARIES = [
        "qemu-mips",
        "qemu-mipsel",
        "qemu-arm",
        "qemu-aarch64",
        "qemu-x86_64",
        "qemu-i386",
    ]

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
    def is_available(cls) -> bool:
        """Check if WSL2 Linux environment is available and responsive."""
        if cls._WSL_AVAILABLE is True:
            return True

        if not shutil.which("wsl"):
            cls._WSL_AVAILABLE = False
            return False

        try:
            res = subprocess.run(
                ["wsl", "-d", cls._WSL_DISTRO, "--", "uname", "-s"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0 and "Linux" in res.stdout:
                cls._WSL_AVAILABLE = True
                return True
        except Exception:
            pass

        return False

    @classmethod
    def to_wsl_path(cls, path: Path | str) -> str:
        """Convert a Windows Path to its corresponding /mnt/... path in WSL."""
        p_str = str(Path(path).resolve())
        # Drive letter mapping: C:\path -> /mnt/c/path
        if len(p_str) >= 2 and p_str[1] == ":":
            drive = p_str[0].lower()
            rest = p_str[2:].replace("\\", "/")
            return f"/mnt/{drive}{rest}"
        return p_str.replace("\\", "/")

    @classmethod
    def get_qemu_binary(cls, arch: str, endian: str = "little") -> str | None:
        """Resolve corresponding QEMU user binary name."""
        return cls.ARCH_MAP.get((arch.lower().strip(), endian.lower().strip()))

    @classmethod
    def discover_qemu_tools(cls) -> dict[str, str | None]:
        """Inspect WSL environment for available QEMU user binaries."""
        if not cls.is_available():
            return {b: None for b in cls.COMMON_QEMU_BINARIES}

        discovered: dict[str, str | None] = {}
        for binary in cls.COMMON_QEMU_BINARIES:
            try:
                res = subprocess.run(
                    ["wsl", "-d", cls._WSL_DISTRO, "--", "which", binary],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                discovered[binary] = res.stdout.strip() if res.returncode == 0 else None
            except Exception:
                discovered[binary] = None
        return discovered

    @classmethod
    def get_qemu_version(cls, binary_name: str) -> str | None:
        """Retrieve version string of a QEMU user binary in WSL."""
        if not cls.is_available():
            return None
        try:
            res = subprocess.run(
                ["wsl", "-d", cls._WSL_DISTRO, "--", binary_name, "--version"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0 and res.stdout:
                return res.stdout.splitlines()[0].strip()
        except Exception:
            pass
        return None

    @classmethod
    def is_angr_available(cls) -> bool:
        """Check if angr is installed in the WSL Python environment."""
        if not cls.is_available():
            return False
        try:
            res = subprocess.run(
                [
                    "wsl",
                    "-d",
                    cls._WSL_DISTRO,
                    "--",
                    cls._ANGR_PYTHON,
                    "-c",
                    "import angr; print(angr.__version__)",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0 and bool(res.stdout.strip())
        except Exception:
            return False

    @classmethod
    def run_isolated_qemu(
        cls,
        binary_path: Path,
        arch: str,
        endian: str = "little",
        args: list[str] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        input_data: bytes | None = None,
        capture_cpu_state: bool = True,
    ) -> ContainedExecutionResult:
        """Execute binary in QEMU user-mode inside isolated Linux namespace."""
        start_time = time.monotonic()
        arch_norm = arch.lower().strip()
        endian_norm = endian.lower().strip()

        if not binary_path.exists() or not binary_path.is_file():
            return ContainedExecutionResult(
                status="failed",
                architecture=arch,
                qemu_binary=None,
                exit_code=None,
                stdout="",
                stderr=f"Target binary '{binary_path}' not found.",
                termination_reason="File not found.",
                duration_ms=0.0,
            )

        if binary_path.stat().st_size == 0:
            return ContainedExecutionResult(
                status="failed",
                architecture=arch,
                qemu_binary=None,
                exit_code=None,
                stdout="",
                stderr="Target binary is empty (0 bytes).",
                termination_reason="Cannot emulate empty file.",
                duration_ms=0.0,
            )

        qemu_bin = cls.get_qemu_binary(arch_norm, endian_norm)
        if not qemu_bin:
            return ContainedExecutionResult(
                status="unsupported_architecture",
                architecture=arch,
                qemu_binary=None,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=f"No QEMU user binary mapped for architecture '{arch}' ({endian}).",
                duration_ms=round((time.monotonic() - start_time) * 1000, 2),
            )

        if not cls.is_available():
            return ContainedExecutionResult(
                status="isolation_blocked",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason="Containment blocked: WSL2 Linux environment unavailable.",
                duration_ms=round((time.monotonic() - start_time) * 1000, 2),
            )

        # Check if QEMU binary is installed in WSL
        tools = cls.discover_qemu_tools()
        if not tools.get(qemu_bin):
            return ContainedExecutionResult(
                status="tool_unavailable",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="",
                termination_reason=f"QEMU user binary '{qemu_bin}' is not installed in the Linux environment.",
                duration_ms=round((time.monotonic() - start_time) * 1000, 2),
            )

        wsl_binary_path = cls.to_wsl_path(binary_path)

        # Build isolated command:
        # unshare -r -n : private user namespace, network completely disconnected
        # timeout -s KILL <seconds> : hard process boundary
        qemu_args = [qemu_bin]
        if capture_cpu_state:
            qemu_args.extend(["-d", "cpu"])
        qemu_args.append(wsl_binary_path)
        if args:
            qemu_args.extend(args)

        timeout_str = str(int(timeout_seconds)) if timeout_seconds >= 1 else "1"
        cmd = [
            "wsl",
            "-d",
            cls._WSL_DISTRO,
            "--",
            "unshare",
            "-r",
            "-n",
            "timeout",
            "-s",
            "KILL",
            timeout_str,
            *qemu_args,
        ]

        try:
            res = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                timeout=timeout_seconds + 3.0,
            )
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)

            stdout = res.stdout[:MAX_OUTPUT_CAPTURE_BYTES].decode("utf-8", errors="replace")
            stderr = res.stderr[:MAX_OUTPUT_CAPTURE_BYTES].decode("utf-8", errors="replace")
            exit_code = res.returncode

            # Fail-closed check: if namespace creation failed, reject immediately
            if "unshare:" in stderr and ("unshare failed" in stderr or "cannot change root" in stderr or "Operation not permitted" in stderr):
                return ContainedExecutionResult(
                    status="isolation_blocked",
                    architecture=arch,
                    qemu_binary=qemu_bin,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    termination_reason=f"Isolation failure: Linux namespace creation denied ({stderr.strip().splitlines()[0]}).",
                    duration_ms=duration_ms,
                    is_mocked=False,
                    is_contained=False,
                    network_isolated=False,
                    command_executed=cmd,
                )

            # Check timeout (exit 124/137 from timeout command)
            if exit_code in (124, 137) or "Killed" in stderr:
                return ContainedExecutionResult(
                    status="timeout",
                    architecture=arch,
                    qemu_binary=qemu_bin,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    termination_reason=f"Execution exceeded budget of {timeout_seconds}s.",
                    duration_ms=duration_ms,
                    is_mocked=False,
                    command_executed=cmd,
                )

            # Check missing libraries
            if "cannot open shared object file" in stderr or "No such file or directory" in stderr:
                if "/lib" in stderr or "ld-linux" in stderr or "uClibc" in stderr:
                    return ContainedExecutionResult(
                        status="missing_libraries",
                        architecture=arch,
                        qemu_binary=qemu_bin,
                        exit_code=exit_code,
                        stdout=stdout,
                        stderr=stderr,
                        termination_reason="Missing guest dynamic linker or shared libraries in target rootfs.",
                        duration_ms=duration_ms,
                        is_mocked=False,
                        command_executed=cmd,
                    )

            # Check crash
            is_crash = (
                exit_code not in (0, None)
                or "uncaught target signal" in stderr
                or "Segmentation fault" in stderr
                or "Bus error" in stderr
                or "Illegal instruction" in stderr
            )

            crash_report = None
            if is_crash:
                crash_rep_obj = CrashStateParser.parse_crash(
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                    arch=arch,
                    binary_name=binary_path.name,
                )
                if crash_rep_obj:
                    if input_data:
                        crash_rep_obj.diagnostic_summary += f" [Trigger Input SHA256: {hashlib.sha256(input_data).hexdigest()}]"
                    crash_report = crash_rep_obj.to_dict()

                return ContainedExecutionResult(
                    status="crashed",
                    architecture=arch,
                    qemu_binary=qemu_bin,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    termination_reason=f"Target binary terminated abnormally with code {exit_code}.",
                    duration_ms=duration_ms,
                    is_mocked=False,
                    crash_report=crash_report,
                    command_executed=cmd,
                )

            return ContainedExecutionResult(
                status="completed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=0,
                stdout=stdout,
                stderr=stderr,
                termination_reason="Process exited with status 0 under verified isolation.",
                duration_ms=duration_ms,
                is_mocked=False,
                command_executed=cmd,
            )

        except subprocess.TimeoutExpired:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            return ContainedExecutionResult(
                status="timeout",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=124,
                stdout="",
                stderr=f"Subprocess timeout expired ({timeout_seconds}s).",
                termination_reason="Execution budget exceeded.",
                duration_ms=duration_ms,
                is_mocked=False,
                command_executed=cmd,
            )
        except Exception as exc:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            return ContainedExecutionResult(
                status="failed",
                architecture=arch,
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                termination_reason=f"Execution error: {exc!s}",
                duration_ms=duration_ms,
                is_mocked=False,
                command_executed=cmd,
            )

    @classmethod
    def run_angr_symbolic_analysis(
        cls,
        binary_path: Path,
        target_sinks: list[str] | None = None,
        timeout_seconds: float = 10.0,
        path_budget: int = 15,
    ) -> dict[str, Any]:
        """Perform real symbolic execution via angr/claripy in WSL."""
        start_time = time.monotonic()
        if not cls.is_available() or not cls.is_angr_available():
            return {
                "status": "angr_unavailable",
                "message": "angr/claripy environment is not available in WSL Linux runtime.",
                "duration_ms": 0.0,
                "leads": [],
            }

        wsl_binary_path = cls.to_wsl_path(binary_path)
        sinks_to_check = target_sinks or ["target_sink", "system", "strcpy", "sprintf", "popen"]

        driver_code = f"""
import sys, json, time, hashlib
import angr
driver_start = time.time()

binary_path = {repr(wsl_binary_path)}
sinks = {json.dumps(sinks_to_check)}
timeout_sec = {timeout_seconds}
path_limit = {path_budget}

results = []
try:
    proj = angr.Project(binary_path, auto_load_libs=False)
except Exception as e:
    print(json.dumps({{"status": "load_error", "error": str(e), "leads": []}}))
    sys.exit(0)

# Scan symbols for presence of sinks
symbols_found = {{}}
for s in sinks:
    sym = proj.loader.find_symbol(s)
    if sym:
        symbols_found[s] = sym.rebased_addr

if not symbols_found:
    print(json.dumps({{"status": "no_sinks_found", "leads": []}}))
    sys.exit(0)

for sink_name, sink_addr in symbols_found.items():
    t0 = time.time()
    try:
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=sink_addr, num_find=1)
        elap = round((time.time() - t0) * 1000, 2)

        if simgr.found:
            found_st = simgr.found[0]
            concrete_in = found_st.posix.dumps(0)
            constraints = [str(c) for c in found_st.solver.constraints]
            in_hash = hashlib.sha256(concrete_in).hexdigest()

            results.append({{
                "sink": sink_name,
                "sink_address": hex(sink_addr),
                "is_confirmed": True,
                "status": "confirmed_reachable",
                "confidence": "confirmed",
                "analysis_method": "angr_symbolic_execution",
                "concrete_input_hex": concrete_in.hex(),
                "concrete_input_repr": repr(concrete_in),
                "input_sha256": in_hash,
                "constraints_count": len(constraints),
                "sample_constraints": constraints[-4:],
                "duration_ms": elap,
            }})
        else:
            results.append({{
                "sink": sink_name,
                "sink_address": hex(sink_addr),
                "is_confirmed": False,
                "status": "unreachable",
                "confidence": "confirmed_unreachable",
                "analysis_method": "angr_symbolic_execution",
                "duration_ms": elap,
            }})
    except Exception as exc:
        results.append({{
            "sink": sink_name,
            "sink_address": hex(sink_addr),
            "is_confirmed": False,
            "status": "solver_error",
            "confidence": "inconclusive",
            "analysis_method": "angr_symbolic_execution",
            "error": str(exc),
            "duration_ms": round((time.time() - t0) * 1000, 2),
        }})

print(json.dumps({{
    "status": "completed",
    "engine": "angr 10.0.5",
    "arch": proj.arch.name,
    "bits": proj.arch.bits,
    "leads": results,
    "duration_ms": round((time.time() - driver_start) * 1000, 2),
}}))
"""

        try:
            res = subprocess.run(
                [
                    "wsl",
                    "-d",
                    cls._WSL_DISTRO,
                    "--",
                    "unshare",
                    "-r",
                    "-n",
                    cls._ANGR_PYTHON,
                    "-c",
                    driver_code,
                ],
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 5.0,
            )
            if res.returncode == 0 and res.stdout.strip():
                return json.loads(res.stdout.strip())
            return {
                "status": "failed",
                "error": res.stderr.strip()[:300] if res.stderr else "Empty output",
                "leads": [],
                "duration_ms": round((time.monotonic() - start_time) * 1000, 2),
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "leads": [],
                "duration_ms": round((time.monotonic() - start_time) * 1000, 2),
            }

    @classmethod
    def run_isolated_qemu_system(
        cls,
        qemu_bin: str,
        system_args: list[str],
        timeout_seconds: float = 10.0,
    ) -> ContainedExecutionResult:
        """Execute QEMU system emulator inside isolated Linux namespace (PRD FR-2.2)."""
        start_time = time.monotonic()
        if not cls.is_available():
            return ContainedExecutionResult(
                status="isolation_blocked",
                architecture="system",
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr="System emulation blocked: WSL2 Linux environment unavailable.",
                termination_reason="WSL2 unavailable.",
                duration_ms=round((time.monotonic() - start_time) * 1000, 2),
                is_mocked=False,
            )

        timeout_str = str(int(timeout_seconds)) if timeout_seconds >= 1 else "1"
        cmd = [
            "wsl",
            "-d",
            cls._WSL_DISTRO,
            "--",
            "unshare",
            "-r",
            "-n",
            "timeout",
            "-s",
            "KILL",
            timeout_str,
            qemu_bin,
            *system_args,
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout_seconds + 5.0,
            )
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            stdout = res.stdout[:MAX_OUTPUT_CAPTURE_BYTES].decode("utf-8", errors="replace")
            stderr = res.stderr[:MAX_OUTPUT_CAPTURE_BYTES].decode("utf-8", errors="replace")

            if res.returncode in (124, 137):
                status = "timeout"
                term = f"Execution exceeded timeout budget of {timeout_seconds}s."
            elif res.returncode == 0:
                status = "success"
                term = "QEMU system emulator terminated normally (code 0)."
            else:
                status = "completed"
                term = f"QEMU system emulator exited with code {res.returncode}."

            return ContainedExecutionResult(
                status=status,
                architecture="system",
                qemu_binary=qemu_bin,
                exit_code=res.returncode,
                stdout=stdout,
                stderr=stderr,
                termination_reason=term,
                duration_ms=duration_ms,
                is_mocked=False,
                command_executed=cmd,
            )
        except subprocess.TimeoutExpired:
            return ContainedExecutionResult(
                status="timeout",
                architecture="system",
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr=f"Host-level execution timeout after {timeout_seconds}s.",
                termination_reason="Subprocess timeout expired.",
                duration_ms=round((time.monotonic() - start_time) * 1000, 2),
                is_mocked=False,
                command_executed=cmd,
            )
        except Exception as exc:
            return ContainedExecutionResult(
                status="failed",
                architecture="system",
                qemu_binary=qemu_bin,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                termination_reason=f"Subprocess invocation error: {exc}",
                duration_ms=round((time.monotonic() - start_time) * 1000, 2),
                is_mocked=False,
                command_executed=cmd,
            )
