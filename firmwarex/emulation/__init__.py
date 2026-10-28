"""FirmwareX Emulation & Dynamic Execution Adapter Package.

Provides architecture mapping, tool discovery, bounded user-mode analysis,
isolation preflight enforcement, and safe diagnostic capture for IoT binaries.
"""

from firmwarex.emulation.qemu_adapter import (
    EmulationResult,
    QemuArchitectureMapper,
    QemuEmulationAdapter,
    QemuToolDiscovery,
)

__all__ = [
    "EmulationResult",
    "QemuArchitectureMapper",
    "QemuEmulationAdapter",
    "QemuToolDiscovery",
]
