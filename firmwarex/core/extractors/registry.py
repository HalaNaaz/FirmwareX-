"""Central registry and dispatch coordinator for modular firmware extractors."""

from pathlib import Path

from firmwarex.core.extractors.archive_extractor import ArchiveExtractor
from firmwarex.core.extractors.base import (
    BaseExtractor,
    ExtractionOutcome,
    ExtractionStatus,
    QuotaTracker,
)
from firmwarex.core.extractors.cramfs_extractor import CramfsExtractor
from firmwarex.core.extractors.jffs2_ubifs_extractor import Jffs2Extractor, UbifsExtractor
from firmwarex.core.extractors.squashfs_extractor import SquashfsExtractor
from firmwarex.core.extractors.trx_extractor import TrxExtractor
from firmwarex.core.extractors.uimage_extractor import UImageExtractor
from firmwarex.core.raw_detector import RawFirmwareDetector


class ExtractorRegistry:
    """Manages extractor registration, format identification, and safe execution dispatch."""

    def __init__(self):
        self._extractors: list[BaseExtractor] = [
            ArchiveExtractor(),
            CramfsExtractor(),
            TrxExtractor(),
            UImageExtractor(),
            SquashfsExtractor(),
            Jffs2Extractor(),
            UbifsExtractor(),
        ]

    def list_capabilities(self) -> list[dict]:
        """Enumerate registered extractors and tool availability status."""
        capabilities = []
        for ext in self._extractors:
            avail, info = ext.check_tool_availability()
            capabilities.append({
                "format_id": ext.format_id,
                "name": ext.name,
                "is_available": avail,
                "tool_details": info,
            })
        return capabilities

    def find_extractor_for_file(self, file_path: Path, offset: int = 0) -> BaseExtractor | None:
        """Find an extractor capable of handling the data starting at offset."""
        for ext in self._extractors:
            if ext.can_extract(file_path, offset=offset):
                return ext
        return None

    def extract_firmware(
        self,
        file_path: Path,
        output_dir: Path,
        max_file_count: int = 5000,
        max_uncompressed_size: int = 250 * 1024 * 1024,
    ) -> ExtractionOutcome:
        """Coordinated extraction handling container offsets and multi-stage unpacking.

        Raises:
            SecurityViolationError: If quotas or path containment boundaries are breached.
        """
        tracker = QuotaTracker(max_file_count=max_file_count, max_total_bytes=max_uncompressed_size)

        if not file_path.exists():
            return ExtractionOutcome(
                status=ExtractionStatus.FAILED,
                success=False,
                format_id="unknown",
                errors=["Target file does not exist."],
            )

        # 1. Try finding an extractor at offset 0
        extractor = self.find_extractor_for_file(file_path, offset=0)
        chosen_offset = 0

        # 2. If no extractor at offset 0, scan signatures for embedded offsets
        if not extractor:
            signatures = RawFirmwareDetector.scan_signatures(file_path, max_bytes=10 * 1024 * 1024)
            for sig in signatures:
                cand = self.find_extractor_for_file(file_path, offset=sig.offset)
                if cand:
                    extractor = cand
                    chosen_offset = sig.offset
                    break

        if not extractor:
            # Check raw signatures to provide explicit diagnostics
            sigs = RawFirmwareDetector.scan_signatures(file_path, max_bytes=65536)
            sig_name = sigs[0].name if sigs else "Unknown Binary"
            rec_tool = sigs[0].recommended_tool if sigs else "binwalk"
            return ExtractionOutcome(
                status=ExtractionStatus.UNSUPPORTED,
                success=False,
                format_id="raw_or_unsupported",
                diagnostics=[f"Format '{sig_name}' detected but no compatible extractor found. Recommended: {rec_tool}."],
                errors=[f"Unsupported firmware format. External tool required: {rec_tool}."],
            )

        # 3. Execute primary extraction
        output_dir.mkdir(parents=True, exist_ok=True)
        primary_outcome = extractor.extract(
            file_path=file_path,
            output_dir=output_dir,
            offset=chosen_offset,
            quota_tracker=tracker,
        )

        if not primary_outcome.success:
            return primary_outcome

        # 4. If primary extraction was a container (TRX or uImage), inspect extracted partitions for embedded filesystems
        if extractor.format_id in ("trx", "uimage"):
            for part_rel_path in list(primary_outcome.extracted_files):
                part_full_path = output_dir / part_rel_path
                if not part_full_path.is_file():
                    continue

                sub_extractor = self.find_extractor_for_file(part_full_path, offset=0)
                if sub_extractor and sub_extractor.format_id not in ("trx", "uimage"):
                    sub_out_dir = output_dir / f"_extracted_{part_full_path.stem}"
                    sub_outcome = sub_extractor.extract(
                        file_path=part_full_path,
                        output_dir=sub_out_dir,
                        offset=0,
                        quota_tracker=tracker,
                    )
                    if sub_outcome.success:
                        for sf in sub_outcome.extracted_files:
                            rel_to_main = (sub_out_dir / sf).relative_to(output_dir)
                            primary_outcome.extracted_files.append(str(rel_to_main).replace("\\", "/"))
                        primary_outcome.diagnostics.extend(sub_outcome.diagnostics)
                        primary_outcome.file_count = len(primary_outcome.extracted_files)
                        primary_outcome.total_size_bytes = tracker.current_total_bytes

        return primary_outcome
