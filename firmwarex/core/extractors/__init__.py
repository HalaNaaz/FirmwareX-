"""Modular extractor registry and interfaces for FirmwareX.

Supports standard archives (ZIP, TAR, GZ, BZ2, XZ), raw embedded filesystems
(CramFS, SquashFS, JFFS2, UBIFS), and container partitions (Broadcom TRX, U-Boot uImage).
"""

from firmwarex.core.extractors.base import (
    BaseExtractor,
    ExtractionOutcome,
    ExtractionStatus,
    QuotaTracker,
)
from firmwarex.core.extractors.registry import ExtractorRegistry

__all__ = [
    "BaseExtractor",
    "ExtractionOutcome",
    "ExtractionStatus",
    "ExtractorRegistry",
    "QuotaTracker",
]

