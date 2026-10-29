"""Base classes, data types, and quota tracking for firmware extractors."""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path


class ExtractionStatus(str, Enum):
    """Extraction outcome state according to PRD specification."""
    DETECTED = "detected"          # Magic bytes found, extraction not yet attempted
    EXTRACTED = "extracted"        # Filesystem unpacked completely and safely
    PARTIAL = "partial"            # Some layers/partitions extracted, others deferred
    UNSUPPORTED = "unsupported"    # Format recognized but requires external unavailable tooling
    CORRUPTED = "corrupted"        # Damaged headers, CRC failure, or truncated stream
    FAILED = "failed"              # Unhandled internal error or critical system fault


class SecurityViolationError(Exception):
    """Raised when an extraction attempts directory traversal or quota breach."""


class QuotaTracker:
    """Enforces cumulative file count and uncompressed byte quotas across extraction steps."""

    def __init__(self, max_file_count: int = 5000, max_total_bytes: int = 250 * 1024 * 1024):
        self.max_file_count = max_file_count
        self.max_total_bytes = max_total_bytes
        self.current_file_count = 0
        self.current_total_bytes = 0

    def add_file(self, size_bytes: int):
        """Register a new extracted file against the quotas.

        Raises:
            SecurityViolationError: If quotas are exceeded.
        """
        self.current_file_count += 1
        self.current_total_bytes += size_bytes

        if self.current_file_count > self.max_file_count:
            raise SecurityViolationError(
                f"Extraction quota exceeded: File count limit ({self.max_file_count}) reached."
            )
        if self.current_total_bytes > self.max_total_bytes:
            raise SecurityViolationError(
                f"Extraction quota exceeded: Total uncompressed size limit ({self.max_total_bytes} bytes) reached."
            )


@dataclass
class ExtractionOutcome:
    """Standardized result emitted by any modular extractor."""
    status: ExtractionStatus
    success: bool
    format_id: str
    offset: int = 0
    tool_name: str = "builtin"
    tool_version: str | None = None
    file_count: int = 0
    total_size_bytes: int = 0
    extracted_files: list[str] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


def is_safe_extraction_path(base_dir: Path, target_path: Path) -> bool:
    """Verify that target_path strictly resolves inside base_dir (Zip Slip defense)."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_base == resolved_target or resolved_base in resolved_target.parents
    except Exception:
        return False


class BaseExtractor(ABC):
    """Abstract base class for all modular firmware extractors."""

    format_id: str
    name: str

    @abstractmethod
    def check_tool_availability(self) -> tuple[bool, str | None]:
        """Check if required extraction utilities are available.

        Returns:
            (is_available, tool_version_or_path_or_reason)
        """

    @abstractmethod
    def can_extract(self, file_path: Path, offset: int = 0) -> bool:
        """Verify whether this extractor can parse the payload starting at offset."""

    @abstractmethod
    def extract(
        self,
        file_path: Path,
        output_dir: Path,
        offset: int = 0,
        quota_tracker: QuotaTracker | None = None,
    ) -> ExtractionOutcome:
        """Safely extract contents into output_dir enforcing quotas and containment."""

