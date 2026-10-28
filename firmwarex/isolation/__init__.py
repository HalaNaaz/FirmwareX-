"""FirmwareX Isolation & Containment Package.

Enforces zero-host-execution policies, disposable container sandbox profiles,
preflight verification, network egress denial (--network none), and fail-closed safety.
"""

from firmwarex.isolation.sandbox_manager import (
    ContainmentPreflight,
    DisposableSandbox,
    IsolationConfig,
    PreflightCheckResult,
)

__all__ = [
    "ContainmentPreflight",
    "DisposableSandbox",
    "IsolationConfig",
    "PreflightCheckResult",
]
