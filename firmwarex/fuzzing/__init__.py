"""Protocol-aware defensive fuzzing foundation for FirmwareX.

Provides bounded, reproducible mutation testing for HTTP, UPnP, and MQTT services
restricted strictly to loopback (127.0.0.1) test environments.
"""

from firmwarex.fuzzing.protocol_fuzzer import (
    FuzzAnomalyRecord,
    FuzzConfig,
    FuzzProtocol,
    FuzzSessionReport,
    ProtocolFuzzRunner,
    ProtocolMutator,
)
from firmwarex.fuzzing.test_server import SyntheticLocalTestServer

__all__ = [
    "FuzzAnomalyRecord",
    "FuzzConfig",
    "FuzzProtocol",
    "FuzzSessionReport",
    "ProtocolFuzzRunner",
    "ProtocolMutator",
    "SyntheticLocalTestServer",
]

