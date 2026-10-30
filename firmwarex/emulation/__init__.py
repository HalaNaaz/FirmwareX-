"""FirmwareX Emulation & Dynamic Execution Adapter Package.

Provides architecture mapping, tool discovery, bounded user-mode analysis,
best-effort full-system emulation, isolation preflight enforcement, and safe
diagnostic capture for IoT binaries.
"""

from firmwarex.emulation.crash_parser import CrashReport, CrashStateParser
from firmwarex.emulation.qemu_adapter import (
    EmulationResult,
    QemuArchitectureMapper,
    QemuEmulationAdapter,
    QemuSystemArchitectureMapper,
    QemuSystemEmulator,
    QemuToolDiscovery,
    SystemBootResult,
    SystemEmulationConfig,
)

__all__ = [
    "CrashReport",
    "CrashStateParser",
    "EmulationResult",
    "QemuArchitectureMapper",
    "QemuEmulationAdapter",
    "QemuSystemArchitectureMapper",
    "QemuSystemEmulator",
    "QemuToolDiscovery",
    "SystemBootResult",
    "SystemEmulationConfig",
]
