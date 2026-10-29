"""Unit tests for container containment preflight and disposable sandbox isolation."""

from pathlib import Path

from firmwarex.isolation.sandbox_manager import (
    SANDBOX_BASE_DIR,
    ContainmentPreflight,
    DisposableSandbox,
    IsolationConfig,
    PreflightCheckResult,
)


def test_containment_preflight_verifies_docker():
    """Verify live preflight check returns structured telemetry."""
    result = ContainmentPreflight.run_preflight()
    assert isinstance(result, PreflightCheckResult)
    assert isinstance(result.diagnostics, list)
    assert len(result.diagnostics) > 0

    # Structured telemetry reflects environment Docker daemon status
    if result.daemon_responsive:
        assert result.docker_available is True
        assert result.network_isolation_verified is True
        assert result.passed is True
    else:
        assert result.passed is False
        assert any(
            "stopped" in d.lower()
            or "unreachable" in d.lower()
            or "not responsive" in d.lower()
            or "incomplete" in d.lower()
            for d in result.diagnostics
        )


def test_containment_preflight_fails_closed_when_docker_missing(monkeypatch):
    """Verify preflight fails closed and disables emulation if docker CLI is unavailable."""
    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: None)

    result = ContainmentPreflight.run_preflight()
    assert result.passed is False
    assert result.docker_available is False
    assert any("not found" in d.lower() for d in result.diagnostics)


def test_validate_mount_path_enforces_sandboxing():
    """Verify that only designated sandbox subdirectories can be mounted into containers."""
    SANDBOX_BASE_DIR.mkdir(parents=True, exist_ok=True)
    valid_sandbox = SANDBOX_BASE_DIR / "session-12345"

    # Legitimate subfolder
    assert ContainmentPreflight.validate_mount_path(valid_sandbox) is True

    # Rejection of dangerous host paths
    assert ContainmentPreflight.validate_mount_path(Path("C:/Windows/System32")) is False
    assert ContainmentPreflight.validate_mount_path(Path("C:/Users/Hala/.ssh")) is False
    assert ContainmentPreflight.validate_mount_path(Path("/var/run/docker.sock")) is False
    assert ContainmentPreflight.validate_mount_path(Path("C:/Program Files")) is False


def test_disposable_sandbox_lifecycle_cleanup():
    """Verify sandbox directory creation and guaranteed post-session purge."""
    sandbox_id = "test-cleanup-lifecycle"
    sandbox = DisposableSandbox(sandbox_id=sandbox_id)

    with sandbox:
        assert sandbox.sandbox_dir.exists()
        test_file = sandbox.sandbox_dir / "temp_binary.bin"
        test_file.write_bytes(b"\x7fELFfake")
        assert test_file.exists()

    # Post-exit: directory must be purged
    assert not sandbox.sandbox_dir.exists()


def test_disposable_sandbox_docker_run_args():
    """Verify that hardened flags are generated: --network=none, --read-only, --cap-drop=ALL."""
    cfg = IsolationConfig(
        network_mode="none",
        memory_limit="128m",
        timeout_seconds=5,
    )
    sandbox = DisposableSandbox(sandbox_id="test-args-gen", config=cfg)
    with sandbox:
        args = sandbox.build_docker_run_args("firmwarex-base:latest", ["ls", "-la"])
        assert "docker" in args
        assert "run" in args
        assert "--network=none" in args
        assert "--cap-drop=ALL" in args
        assert "--security-opt=no-new-privileges:true" in args
        assert "--read-only" in args
        assert "--memory=128m" in args
        assert "-v" in args
        assert "/workspace:ro" in args[args.index("-v") + 1]
