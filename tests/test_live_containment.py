"""Tests for disposable container containment execution and live isolation verification.

Verifies:
1. Argument-list based command execution (no shell interpolation).
2. Path mount isolation boundaries (rejecting docker.sock, root paths).
3. Live container execution with --network none, read-only rootfs, and non-root user.
4. Guaranteed disposable sandbox cleanup.
"""

from pathlib import Path

import pytest

from firmwarex.isolation.sandbox_manager import (
    ContainmentPreflight,
    DisposableSandbox,
)


def test_command_must_be_list_of_strings():
    """Verify shell-string commands are rejected to prevent shell interpolation."""
    with DisposableSandbox() as sandbox:
        # Invalid: passing a raw string instead of a list
        res = sandbox.execute_isolated_command("echo 123")  # type: ignore
        assert res.status == "failed"
        assert "command must be a list of string arguments" in res.stderr


def test_mount_path_enforcement_blocks_unauthorized_paths():
    """Verify mount path validation blocks unauthorized directories outside sandbox base."""
    # Forbidden target like Windows root or user home
    forbidden = Path("C:/Windows/System32")
    assert ContainmentPreflight.validate_mount_path(forbidden) is False


def test_disposable_sandbox_directory_cleanup(tmp_path):
    """Verify disposable sandbox directory is strictly purged upon context exit."""
    sandbox_dir = None
    with DisposableSandbox() as sandbox:
        sandbox_dir = sandbox.sandbox_dir
        assert sandbox_dir.exists()
        # Create a test scratch file inside
        (sandbox_dir / "scratch.tmp").write_text("temporary scratch data")
        assert (sandbox_dir / "scratch.tmp").exists()

    # After exit, sandbox directory must be purged
    assert not sandbox_dir.exists()


def test_live_docker_containment_execution():
    """Verify live container execution with --network none, read-only rootfs, and non-root user.

    Runs an innocuous probe inside local redis:7-alpine image.
    """
    preflight = ContainmentPreflight.run_preflight()
    if not preflight.passed:
        pytest.skip("Docker daemon unavailable or containment preflight failed.")

    with DisposableSandbox() as sandbox:
        # Probe: Verify non-root user (id -u)
        res_id = sandbox.execute_isolated_command(
            command=["id", "-u"],
            image="redis:7-alpine",
            timeout_seconds=5,
        )
        assert res_id.status == "completed"
        assert res_id.network_isolated is True
        assert res_id.read_only_rootfs is True
        assert res_id.stdout.strip() == "1000"

        # Probe: Verify read-only root filesystem
        res_ro = sandbox.execute_isolated_command(
            command=["touch", "/test_ro_file.txt"],
            image="redis:7-alpine",
            timeout_seconds=5,
        )
        assert res_ro.exit_code != 0
        assert "read-only" in res_ro.stderr.lower()

        # Probe: Verify strict network egress denial (--network none)
        res_net = sandbox.execute_isolated_command(
            command=["ping", "-c", "1", "-W", "1", "8.8.8.8"],
            image="redis:7-alpine",
            timeout_seconds=5,
        )
        assert res_net.exit_code != 0
        assert "unreachable" in (res_net.stderr + res_net.stdout).lower()


def test_live_containment_verification_telemetry():
    """Verify ContainmentPreflight.verify_live_containment reports genuine container isolation."""
    preflight = ContainmentPreflight.run_preflight()
    if not preflight.passed:
        pytest.skip("Docker daemon unavailable.")

    report = ContainmentPreflight.verify_live_containment(image="redis:7-alpine")
    assert report["live_execution_verified"] is True
    assert report["network_egress_denied"] is True
    assert report["read_only_rootfs_verified"] is True
    assert report["non_root_verified"] is True
    assert len(report["diagnostics"]) >= 3
