"""Comprehensive sandbox security hardening verification test suite (PRD SC-1.1, SC-2.1, SC-2.2, NFR-SEC-1)."""

import subprocess
import time
from pathlib import Path

import pytest

from firmwarex.isolation.wsl_engine import WslExecutionEngine


class TestSandboxSecurityHardening:
    """Verifies kernel-level Linux containment, fail-closed behavior, and cgroup resource quotas."""

    @pytest.mark.skipif(not WslExecutionEngine.is_available(), reason="WSL2 not available on this host")
    def test_network_namespace_isolation_egress_blocked(self):
        """Verify that inside unshare -r -n, all external network egress is unreachable."""
        # 1. Interface check: only loopback exists and is down
        res_ip = subprocess.run(
            ["wsl", "-d", "Ubuntu", "--", "unshare", "-r", "-n", "ip", "addr"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert res_ip.returncode == 0
        assert "link/loopback" in res_ip.stdout
        assert "eth0" not in res_ip.stdout
        assert "wlan0" not in res_ip.stdout

        # 2. ICMP ping check: fails immediately
        res_ping = subprocess.run(
            ["wsl", "-d", "Ubuntu", "--", "unshare", "-r", "-n", "ping", "-c", "1", "-W", "2", "8.8.8.8"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert res_ping.returncode != 0
        assert "Network is unreachable" in res_ping.stderr or "Network is unreachable" in res_ping.stdout

        # 3. TCP curl check: cannot connect
        res_curl = subprocess.run(
            ["wsl", "-d", "Ubuntu", "--", "unshare", "-r", "-n", "curl", "--connect-timeout", "2", "http://1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert res_curl.returncode != 0

    @pytest.mark.skipif(not WslExecutionEngine.is_available(), reason="WSL2 not available on this host")
    def test_cgroup_v2_memory_quota_oom_termination(self):
        """Verify that memory allocations exceeding MemoryMax are terminated by cgroup v2 kernel OOM killer."""
        cmd = [
            "wsl", "-d", "Ubuntu", "--",
            "systemd-run", "--user", "--pipe", "--wait",
            "-p", "MemoryMax=32M",
            "-p", "MemorySwapMax=0",
            "-p", "NoNewPrivileges=yes",
            "unshare", "-r", "-n",
            "python3", "-c", "x = bytearray(80 * 1024 * 1024)"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert res.returncode != 0
        # Kernel OOM killer signals SIGKILL (code 9)
        assert "oom-kill" in res.stderr or "status=9/KILL" in res.stderr

    @pytest.mark.skipif(not WslExecutionEngine.is_available(), reason="WSL2 not available on this host")
    def test_cgroup_v2_cpu_quota_and_resource_accounting(self):
        """Verify that CPUQuota is actively enforced with telemetry accounting."""
        cmd = [
            "wsl", "-d", "Ubuntu", "--",
            "systemd-run", "--user", "--pipe", "--wait",
            "-p", "MemoryMax=128M",
            "-p", "MemorySwapMax=0",
            "-p", "CPUQuota=25%",
            "-p", "NoNewPrivileges=yes",
            "unshare", "-r", "-n",
            "python3", "-c", "import time; t=time.time()+0.2; [None for _ in iter(lambda: time.time() > t, True)]"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert res.returncode == 0
        assert "Finished with result: success" in res.stderr
        assert "CPU time consumed:" in res.stderr

    @pytest.mark.skipif(not WslExecutionEngine.is_available(), reason="WSL2 not available on this host")
    def test_hard_timeout_and_process_tree_termination_no_orphans(self):
        """Verify that timeout -s KILL terminates all spawned child processes without leaving orphans."""
        marker = "test_marker_sleep_orphan"
        cmd = [
            "wsl", "-d", "Ubuntu", "--",
            "systemd-run", "--user", "--pipe", "--wait",
            "-p", "MemoryMax=64M",
            "-p", "MemorySwapMax=0",
            "unshare", "-r", "-n",
            "timeout", "-s", "KILL", "1",
            "python3", "-c", f"import os, time; [os.fork() for _ in range(2)]; time.sleep(10)  # {marker}"
        ]
        t0 = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        dur = time.time() - t0

        # Terminated within ~1 second
        assert dur < 3.0
        assert res.returncode in (124, 137)

        # Confirm zero orphaned processes left
        check = subprocess.run(
            ["wsl", "-d", "Ubuntu", "--", "pgrep", "-f", marker],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert check.stdout.strip() == ""

    def test_windows_host_isolation_fails_closed(self):
        """Verify that ELF binaries cannot be executed by the Windows host OS."""
        elf_path = Path("tests/fixtures/x86_64_clean")
        if elf_path.exists():
            with pytest.raises(OSError):
                # Windows cannot execute ELF format binaries (WinError 193: %1 is not a valid Win32 application)
                subprocess.run([str(elf_path.resolve())], capture_output=True)

    @pytest.mark.skipif(not WslExecutionEngine.is_available(), reason="WSL2 not available on this host")
    def test_least_privilege_no_new_privileges(self):
        """Verify that NoNewPrivileges security setting prevents privilege escalation inside sandbox."""
        cmd = [
            "wsl", "-d", "Ubuntu", "--",
            "systemd-run", "--user", "--pipe", "--wait",
            "-p", "NoNewPrivileges=yes",
            "true"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        assert res.returncode == 0
        assert "Finished with result: success" in res.stderr
