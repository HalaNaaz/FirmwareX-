"""Protocol-aware defensive fuzzing foundation for FirmwareX.

Provides bounded, reproducible mutation testing for HTTP, UPnP, and MQTT services
restricted strictly to loopback (127.0.0.1) test environments, along with seed corpus
management, bounded crash minimization, and backtrace fingerprint deduplication.
"""

from firmwarex.fuzzing.corpus_manager import CorpusManager, SeedMetadata
from firmwarex.fuzzing.crash_deduplicator import CrashDeduplicator, CrashFingerprint, CrashGroup
from firmwarex.fuzzing.minimizer import CrashInputMinimizer, MinimizationResult
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
    "CorpusManager",
    "CrashDeduplicator",
    "CrashFingerprint",
    "CrashGroup",
    "CrashInputMinimizer",
    "FuzzAnomalyRecord",
    "FuzzConfig",
    "FuzzProtocol",
    "FuzzSessionReport",
    "MinimizationResult",
    "ProtocolFuzzRunner",
    "ProtocolMutator",
    "SeedMetadata",
    "SyntheticLocalTestServer",
]
